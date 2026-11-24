/*
  ================================================================
   Advanced IoT-Based Smart Classroom Security, Safety and
   Automation System  -  ESP32 firmware
  ================================================================
   Serves the web dashboard (data/index.html) from LittleFS and
   provides the JSON API the dashboard uses.

   One ESP32 = one classroom (CLASS_ID below). The dashboard can
   still store several classes, cards and timetables, but live
   sensor data comes only from the room this board is in.

   Libraries (Arduino IDE > Library Manager):
     - ESP Async WebServer  (by ESP32Async)
     - Async TCP            (by ESP32Async)
     - ArduinoJson          (by Benoit Blanchon, v7)
     - MFRC522              (by GithubCommunity / miguelbalboa)
     - ESP32Servo           (by Kevin Harrington)
     - LiquidCrystal I2C    (by Frank de Brabander)
   Board: "ESP32 Dev Module" (esp32 by Espressif Systems, 3.x)
  ================================================================
*/
#include <ArduinoJson.h>          // must come before ESPAsyncWebServer.h
#include <WiFi.h>
#include <ESPAsyncWebServer.h>
#include <LittleFS.h>
#include <SPI.h>
#include <MFRC522.h>
#include <ESP32Servo.h>
#include <Wire.h>
#include <LiquidCrystal_I2C.h>
#include <HTTPClient.h>
#include <WiFiClientSecure.h>
#include <time.h>
#include <map>
#include <vector>

// ---------------- USER SETTINGS ----------------
const char* WIFI_SSID = "ZTE Blade A34";
const char* WIFI_PASS = "12345678";
const char* CLASS_ID  = "10A";            // must match the class id used in the dashboard
const long  GMT_OFFSET_SEC = 19800;       // Sri Lanka = UTC +5:30

// ---- Firebase cloud (leave FIREBASE_API_KEY empty to run local-only) ----
const char* FIREBASE_API_KEY  = "AIzaSyA7xXK06kY8FRj-vxiGAk4WvbYNcrHwCcQ";       // Project settings > General > Web API key
const char* FIREBASE_DB_URL   = "https://smart-class-d2dbc-default-rtdb.asia-southeast1.firebasedatabase.app";       // e.g. https://smart-classroom-xxxx-default-rtdb.asia-southeast1.firebasedatabase.app
const char* DEVICE_EMAIL      = "esp32@school.lk";       // the ESP32's own login (Authentication > Users)
const char* DEVICE_PASSWORD   = "ESP@123";

// Dashboard logins (change these!)
struct Login { const char* user; const char* pass; const char* role; const char* name; };
const Login LOGINS[] = {
  {"admin",   "admin123",   "Admin",   "Admin"},
  {"teacher", "teacher123", "Teacher", "Mr. Perera"},
};

// ---------------- PINS (no conflicts) ----------------
// Pins as wired on the breadboard
#define PIN_LCD_SDA  21      // LCD display SDA
#define PIN_LCD_SCL  22      // LCD display SCL
#define PIN_RFID_SS   5      // RC522 SDA
#define PIN_SPI_SCK  18      // RC522 SCK
#define PIN_SPI_MOSI 23      // RC522 MOSI
#define PIN_SPI_MISO 19      // RC522 MISO
#define PIN_RFID_RST 15      // RC522 RST
#define PIN_MQ2      34      // MQ-2 analogue out (use a voltage divider if the module runs on 5V)
#define PIN_PIR      27      // motion sensor OUT
#define PIN_SERVO    13      // servo signal
#define PIN_RELAY_FAN   26   // fan
#define PIN_BUZZER   25      // optional: buzzer (nothing happens if not connected)
#define PIN_RELAY_LIGHT 32   // optional: lights relay (nothing happens if not connected)

// Fan output: relay modules usually switch ON with LOW.
// If the fan runs when it should be OFF (or you use a transistor/MOSFET), swap LOW and HIGH here.
#define RELAY_ON  LOW
#define RELAY_OFF HIGH
#define SERVO_LOCKED 0
#define SERVO_OPEN   90

// ---------------- OBJECTS ----------------
AsyncWebServer server(80);
MFRC522 rfid(PIN_RFID_SS, PIN_RFID_RST);
Servo doorServo;
LiquidCrystal_I2C lcd(0x27, 16, 2);       // change to 0x3F if your I2C scanner showed that address

// ---------------- DATA ----------------
struct Card { String uid, name, role, classId; bool blocked; };
std::vector<Card> cards;

// Must be defined up here (before any function) so the Arduino IDE's auto-generated
// prototypes for currentPeriod() / isInterval() can see the type.
struct Period { String period, start, end, subject, teacher; bool found = false; };

struct Att { String status = "absent"; String prev = "present"; uint64_t inTime = 0, outSince = 0;
             int lateMin = 0, breaks = 0; bool breakAlertSent = false; };
std::map<String, Att> attendance;          // today's attendance, key = card UID

struct LogItem { uint64_t t; String msg; String type; };
std::vector<LogItem> logs;

struct Settings { int breakLimit = 10, lateAfter = 10, teacherAlert = 5, gas = 3600, doorSec = 5;
                  String tgToken, tgChat, waPhone, waKey; bool tgGas = true, tgIntr = true, tgTeach = true, tgBrk = false, tgBlocked = true; } cfg;

bool sessionActive = false;  uint64_t sessionArrivedAt = 0;  String sessionTeacher;
bool lightOn = false, fanOn = false, doorOpen = false;
unsigned long doorCloseAtMs = 0;
int  gasValue = 0;           bool motion = false;
String lastUid;              uint64_t lastUidAt = 0;
String today;                String lastTeacherAlertPeriod;

bool emergency = false;      uint64_t emergencyAt = 0;  String emergencyReason;
std::vector<String> safeList;

std::vector<String> telegramQueue;
std::vector<String> whatsappQueue;      // WhatsApp alerts through the CallMeBot API

// Web requests run in a separate task. They never touch the live data directly:
// they push commands that loop() executes, and read a status snapshot built by loop().
SemaphoreHandle_t lock;
std::vector<String> commands;
String statusCache = "{}", lastUidCache = "{\"uid\":\"\",\"t\":0}";
void pushCommand(const String& c) { xSemaphoreTake(lock, portMAX_DELAY); commands.push_back(c); xSemaphoreGive(lock); }
String readLocked(const String& s) { xSemaphoreTake(lock, portMAX_DELAY); String c = s; xSemaphoreGive(lock); return c; }
unsigned long lastIntrusionAlert = 0, lastBeep = 0, lcdUntil = 0;

// ---------------- HELPERS ----------------
uint64_t nowMs() { time_t t = time(nullptr); return t > 100000 ? (uint64_t)t * 1000ULL : millis(); }
bool timeReady() { return time(nullptr) > 100000; }

String dateStr() {
  struct tm ti; if (!getLocalTime(&ti, 10)) return "1970-01-01";
  char b[11]; strftime(b, sizeof(b), "%Y-%m-%d", &ti); return String(b);
}
String dayName() {
  struct tm ti; if (!getLocalTime(&ti, 10)) return "";
  const char* d[] = {"Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"};
  return d[ti.tm_wday];
}
int minuteOfDay() { struct tm ti; if (!getLocalTime(&ti, 10)) return -1; return ti.tm_hour * 60 + ti.tm_min; }
int toMin(const String& hhmm) { return hhmm.substring(0, 2).toInt() * 60 + hhmm.substring(3, 5).toInt(); }

void addLog(const String& msg, const String& type) {
  logs.push_back({nowMs(), msg, type});
  if (logs.size() > 40) logs.erase(logs.begin());
  Serial.println("[LOG] " + msg);
}

void lcdShow(const String& a, const String& b, unsigned long holdMs = 3000) {
  lcd.clear(); lcd.setCursor(0, 0); lcd.print(a.substring(0, 16));
  lcd.setCursor(0, 1); lcd.print(b.substring(0, 16));
  lcdUntil = millis() + holdMs;
}

void beep(int times, int onMs = 120) {
  for (int i = 0; i < times; i++) { digitalWrite(PIN_BUZZER, HIGH); delay(onMs); digitalWrite(PIN_BUZZER, LOW); delay(90); }
}

void setLight(bool on) { lightOn = on; digitalWrite(PIN_RELAY_LIGHT, on ? RELAY_ON : RELAY_OFF); }
void setFan(bool on)   { fanOn = on;   digitalWrite(PIN_RELAY_FAN,   on ? RELAY_ON : RELAY_OFF); }
void openDoor(bool keepOpen = false) {
  doorServo.write(SERVO_OPEN); doorOpen = true;
  doorCloseAtMs = keepOpen ? 0 : millis() + cfg.doorSec * 1000UL;
}
void lockDoor() { doorServo.write(SERVO_LOCKED); doorOpen = false; doorCloseAtMs = 0; }

String urlEncode(const String& s) {
  String o; char h[4];
  for (size_t i = 0; i < s.length(); i++) {
    char c = s[i];
    if (isalnum((unsigned char)c) || c == '-' || c == '_' || c == '.' || c == '~') o += c;
    else { snprintf(h, sizeof(h), "%%%02X", (unsigned char)c); o += h; }
  }
  return o;
}
void telegram(const String& msg) {     // every alert goes to Telegram and, if set up, WhatsApp
  if (cfg.tgToken.length() && cfg.tgChat.length()) telegramQueue.push_back(msg);
  if (cfg.waPhone.length() && cfg.waKey.length()) whatsappQueue.push_back(msg);
}

void sendTelegramQueue() {            // runs in loop(), never inside a web request
  if (telegramQueue.empty() || WiFi.status() != WL_CONNECTED) return;
  String msg = telegramQueue.front(); telegramQueue.erase(telegramQueue.begin());
  WiFiClientSecure client; client.setInsecure();
  HTTPClient http;
  String url = "https://api.telegram.org/bot" + cfg.tgToken + "/sendMessage?chat_id=" + cfg.tgChat + "&text=" + urlEncode(msg);
  if (http.begin(client, url)) { int code = http.GET(); Serial.printf("Telegram: %d\n", code); http.end(); }
}

void sendWhatsAppQueue() {            // CallMeBot: free gateway that sends WhatsApp messages to your own number
  if (whatsappQueue.empty() || WiFi.status() != WL_CONNECTED) return;
  String msg = whatsappQueue.front(); whatsappQueue.erase(whatsappQueue.begin());
  WiFiClientSecure client; client.setInsecure();
  HTTPClient http;
  String url = "https://api.callmebot.com/whatsapp.php?phone=" + urlEncode(cfg.waPhone) + "&apikey=" + cfg.waKey + "&text=" + urlEncode(msg);
  if (http.begin(client, url)) { int code = http.GET(); Serial.printf("WhatsApp: %d\n", code); http.end(); }
}

// ---------------- FILES ----------------
String readFile(const char* path, const char* fallback) {
  File f = LittleFS.open(path, "r"); if (!f) return fallback;
  String s = f.readString(); f.close(); return s.length() ? s : String(fallback);
}
void writeFile(const char* path, const String& data) {
  File f = LittleFS.open(path, "w"); if (!f) return; f.print(data); f.close();
}

void loadCards() {
  cards.clear();
  JsonDocument doc;
  if (deserializeJson(doc, readFile("/cards.json", "[]"))) return;
  auto add = [](JsonObject c) {
    if (!c.isNull()) cards.push_back({c["uid"] | "", c["name"] | "", c["role"] | "Student", c["classId"] | "", c["blocked"] | false});
  };
  if (doc.is<JsonArray>()) for (JsonObject c : doc.as<JsonArray>()) add(c);
  else for (JsonPair kv : doc.as<JsonObject>()) add(kv.value().as<JsonObject>());   // Firebase may store arrays as objects
  Serial.printf("Loaded %d cards\n", cards.size());
}

void loadSettings() {
  JsonDocument d;
  if (deserializeJson(d, readFile("/settings.json", "{}"))) return;
  cfg.breakLimit = d["breakLimit"] | 10; cfg.lateAfter = d["lateAfter"] | 10; cfg.teacherAlert = d["teacherAlert"] | 5;
  cfg.gas = d["gas"] | 3600; cfg.doorSec = d["doorSec"] | 5;
  cfg.tgToken = d["tg"]["token"] | ""; cfg.tgChat = d["tg"]["chat"] | "";
  cfg.waPhone = d["tg"]["waPhone"] | ""; cfg.waKey = d["tg"]["waKey"] | "";
  cfg.tgGas = d["tg"]["gas"] | true; cfg.tgIntr = d["tg"]["intrusion"] | true; cfg.tgTeach = d["tg"]["teacher"] | true;
  cfg.tgBrk = d["tg"]["brk"] | false; cfg.tgBlocked = d["tg"]["blocked"] | true;
}

Card* findCard(const String& uid) { for (auto& c : cards) if (c.uid == uid) return &c; return nullptr; }

// ---------------- TIMETABLE ----------------
std::vector<Period> todaysPeriods;     // this class, today only. Reloaded on change or new day
void loadTimetable() {
  todaysPeriods.clear();
  JsonDocument doc;
  if (deserializeJson(doc, readFile("/timetable.json", "[]"))) return;
  String day = dayName();
  JsonArray arr = doc.as<JsonArray>();
  if (!doc.is<JsonArray>()) {                       // Firebase may store arrays as objects
    JsonDocument tmp; JsonArray a = tmp.to<JsonArray>();
    for (JsonPair kv : doc.as<JsonObject>()) a.add(kv.value());
    doc = tmp; arr = doc.as<JsonArray>();
  }
  for (JsonObject x : arr) {
    if (String(x["classId"] | "") != CLASS_ID || String(x["day"] | "") != day) continue;
    Period p; p.period = x["period"] | ""; p.start = x["start"] | "00:00"; p.end = x["end"] | "00:00";
    p.subject = x["subject"] | ""; p.teacher = x["teacher"] | ""; p.found = true;
    todaysPeriods.push_back(p);
  }
  Serial.printf("Timetable: %d periods today (%s)\n", todaysPeriods.size(), day.c_str());
}
Period currentPeriod() {
  int m = minuteOfDay();
  if (m >= 0) for (auto& p : todaysPeriods) if (m >= toMin(p.start) && m < toMin(p.end)) return p;
  return Period();
}
bool isInterval(const Period& p) { return p.found && p.period == "Interval"; }

// ---------------- HISTORY ----------------
// one line per student per day: date,classId,uid,status,lateMin,breaks
std::vector<String> pendingHistory;      // "date|json" waiting to be uploaded to the cloud
void archiveDay(const String& date) {
  JsonDocument hist;
  File f = LittleFS.open("/history.csv", "a"); if (!f) return;
  for (auto& c : cards) {
    if (c.role != "Student" || c.classId != CLASS_ID) continue;
    auto it = attendance.find(c.uid);
    String st = "absent"; int late = 0, brk = 0;
    if (it != attendance.end() && it->second.status != "absent") {
      st = (it->second.status == "late" || it->second.prev == "late") ? "late" : "present";
      late = it->second.lateMin; brk = it->second.breaks;
    }
    f.printf("%s,%s,%s,%s,%d,%d\n", date.c_str(), CLASS_ID, c.uid.c_str(), st.c_str(), late, brk);
    JsonObject h = hist[c.uid].to<JsonObject>(); h["status"] = st; h["lateMin"] = late; h["breaks"] = brk;
  }
  f.close();
  String hs; serializeJson(hist, hs);
  xSemaphoreTake(lock, portMAX_DELAY); pendingHistory.push_back(date + "|" + hs); xSemaphoreGive(lock);
  Serial.println("Archived attendance for " + date);
}

void checkNewDay() {
  if (!timeReady()) return;
  String d = dateStr();
  if (today.length() && d != today) {
    if (!attendance.empty()) archiveDay(today);
    attendance.clear(); sessionActive = false; safeList.clear();
  }
  if (d != today) { today = d; loadTimetable(); }
}

// ---------------- RFID LOGIC ----------------
void handleCard(const String& uid) {
  lastUid = uid; lastUidAt = nowMs();
  Card* c = findCard(uid);

  if (!c || c->blocked) {
    String who = c ? c->name + "'s blocked card" : "Unknown card " + uid;
    addLog("🚫 " + who + " tapped at door", "red");
    lcdShow("ACCESS DENIED", c ? "Card blocked" : "Unknown card");
    beep(3, 80);
    if (cfg.tgBlocked) telegram("🚫 ACCESS DENIED: " + who + " was used at the classroom door.");
    return;
  }

  // During an emergency every student tap counts as "safe at assembly point"
  if (emergency) {
    if (c->role == "Student") {
      bool already = false; for (auto& s : safeList) if (s == uid) already = true;
      if (!already) { safeList.push_back(uid); addLog("✅ " + c->name + " safe at assembly point", "green"); }
      lcdShow("SAFE:", c->name); beep(1, 60);
    }
    return;
  }

  if (c->role == "Admin") {
    openDoor(); addLog("Admin " + c->name + " opened the door", "blue");
    lcdShow("Welcome", c->name); beep(1, 60); return;
  }

  if (c->role == "Teacher") {
    if (!sessionActive) {
      sessionActive = true; sessionArrivedAt = nowMs(); sessionTeacher = c->name;
      setLight(true); setFan(true); openDoor();
      Period p = currentPeriod();
      String subj = (p.found && !isInterval(p)) ? String(" (") + p.subject + ")" : String("");
      addLog("👨‍🏫 " + c->name + " tapped in, class started" + subj, "blue");
      if (p.found && !isInterval(p) && p.teacher.length() && p.teacher != c->name)
        addLog(c->name + " is covering for " + p.teacher + " (relief)", "orange");
      lcdShow("Class Started", c->name); beep(1, 60);
    } else {
      sessionActive = false; openDoor();
      unsigned long mins = (nowMs() - sessionArrivedAt) / 60000ULL;
      addLog("Class ended by " + c->name + " after " + String(mins) + " min", "blue");
      lcdShow("Class Ended", c->name); beep(2, 60);
    }
    return;
  }

  // ---- Student ----
  if (c->classId != CLASS_ID) {
    addLog(c->name + " tried to enter (wrong class)", "orange");
    lcdShow("Wrong class", c->name); beep(2, 80); return;
  }
  Att& a = attendance[uid];
  if (a.status == "absent") {                       // first tap today: arriving
    Period p = currentPeriod();
    int late = 0;
    if (sessionActive && p.found && !isInterval(p)) late = minuteOfDay() - toMin(p.start);
    a.inTime = nowMs();
    if (late > cfg.lateAfter) { a.status = "late"; a.lateMin = late; addLog(c->name + " arrived late (" + String(late) + " min)", "orange"); lcdShow("Late: " + String(late) + " min", c->name); }
    else { a.status = "present"; addLog(c->name + " arrived", "green"); lcdShow("Welcome", c->name); }
    a.prev = a.status; openDoor(); beep(1, 60);
  } else if (a.status == "out") {                   // coming back from a break
    a.status = a.prev; a.breakAlertSent = false;
    unsigned long mins = (nowMs() - a.outSince) / 60000ULL;
    addLog(c->name + " returned (" + String(mins) + " min out)", "green");
    lcdShow("Welcome back", c->name); openDoor(); beep(1, 60);
  } else {                                          // inside -> going out on a break
    a.prev = a.status; a.status = "out"; a.outSince = nowMs(); a.breaks++;
    addLog(c->name + " tapped out (break)", "yellow");
    lcdShow("Break started", c->name); openDoor(); beep(1, 60);
  }
}

// ---------------- EMERGENCY ----------------
void startEmergency(const String& reason) {
  if (emergency) return;
  emergency = true; emergencyAt = nowMs(); emergencyReason = reason; safeList.clear();
  openDoor(true); setFan(true); setLight(true);
  addLog("🚨 EMERGENCY: " + reason + ". Door unlocked, fan on.", "red");
  lcdShow("!! EVACUATE !!", reason, 600000);
  if (cfg.tgGas) telegram("🚨 EMERGENCY in " + String(CLASS_ID) + ": " + reason + ". Door unlocked, ventilation on. Evacuate now.");
}
void endEmergency() {
  if (!emergency) return;
  emergency = false; lockDoor(); digitalWrite(PIN_BUZZER, LOW);
  addLog("Emergency ended. " + String(safeList.size()) + " students marked safe.", "blue");
  lcdUntil = 0;
}

// ---------------- SENSORS + ALERTS ----------------
void checkSensors() {
  static unsigned long last = 0;
  if (millis() - last < 500) return;
  last = millis();

  gasValue = analogRead(PIN_MQ2);
  motion = digitalRead(PIN_PIR) == HIGH;
  Period p = currentPeriod();

  if (millis() > 90000UL && gasValue >= cfg.gas && !emergency) startEmergency("Gas leak detected (" + String(gasValue) + ")");

  // intrusion: motion while no class and no teacher session
  if (timeReady() && motion && !sessionActive && !p.found && !emergency && millis() - lastIntrusionAlert > 60000) {
    lastIntrusionAlert = millis();
    addLog("🚨 Intrusion: motion with no class scheduled", "red");
    lcdShow("INTRUSION!", "Motion detected"); beep(5, 150);
    if (cfg.tgIntr) telegram("🚨 INTRUSION ALERT in " + String(CLASS_ID) + ": motion detected while no class is scheduled.");
  }

  // teacher not arrived
  if (p.found && !isInterval(p) && !sessionActive && minuteOfDay() - toMin(p.start) >= cfg.teacherAlert) {
    String key = today + p.period;
    if (lastTeacherAlertPeriod != key) {
      lastTeacherAlertPeriod = key;
      addLog("Teacher " + p.teacher + " has not arrived for Period " + p.period, "orange");
      if (cfg.tgTeach) telegram("👨‍🏫 " + p.teacher + " has not arrived for Period " + p.period + " (" + p.subject + ") in " + CLASS_ID + ".");
    }
  }

  // break limit (paused during the interval)
  if (!isInterval(p)) for (auto& kv : attendance) {
    Att& a = kv.second;
    if (a.status == "out" && !a.breakAlertSent && (nowMs() - a.outSince) / 60000ULL >= (uint64_t)cfg.breakLimit) {
      a.breakAlertSent = true;
      Card* c = findCard(kv.first); String n = c ? c->name : kv.first;
      addLog(n + " has been out for over " + String(cfg.breakLimit) + " min", "yellow");
      beep(2, 60);
      if (cfg.tgBrk) telegram("🚻 " + n + " has been out of " + String(CLASS_ID) + " for over " + String(cfg.breakLimit) + " minutes.");
    }
  }

  // emergency buzzer pattern
  if (emergency && millis() - lastBeep > 1000) { lastBeep = millis(); digitalWrite(PIN_BUZZER, !digitalRead(PIN_BUZZER)); }

  // idle LCD screen
  if (millis() > lcdUntil && !emergency) {
    lcd.setCursor(0, 0); lcd.print(String(sessionActive ? "In class        " : "Security mode   ").substring(0, 16));
    lcd.setCursor(0, 1); lcd.print(("Gas:" + String(gasValue) + (motion ? " Motion   " : " Clear    ")).substring(0, 16));
  }
}

// ---------------- STATUS SNAPSHOT (built in loop) ----------------
void buildStatus() {
  JsonDocument d;
  d["session"]["active"] = sessionActive;
  d["session"]["arrivedAt"] = sessionArrivedAt;
  JsonObject e = d["env"].to<JsonObject>();
  e["gas"] = gasValue; e["motion"] = motion; e["door"] = doorOpen ? "open" : "locked"; e["light"] = lightOn; e["fan"] = fanOn;
  JsonObject att = d["attendance"].to<JsonObject>();
  for (auto& kv : attendance) {
    JsonObject a = att[kv.first].to<JsonObject>();
    a["status"] = kv.second.status; a["inTime"] = kv.second.inTime;
    a["outSince"] = kv.second.outSince; a["lateMin"] = kv.second.lateMin;
  }
  JsonArray lg = d["log"].to<JsonArray>();
  for (auto& l : logs) { JsonObject o = lg.add<JsonObject>(); o["t"] = l.t; o["msg"] = l.msg; o["type"] = l.type; }
  JsonObject em = d["emergency"].to<JsonObject>();
  em["active"] = emergency; em["startedAt"] = emergencyAt; em["reason"] = emergencyReason;
  JsonArray sl = em["safe"].to<JsonArray>(); for (auto& s : safeList) sl.add(s);
  d["updatedAt"] = nowMs();
  d["lastUid"]["uid"] = lastUid; d["lastUid"]["t"] = lastUidAt;
  String out; serializeJson(d, out);
  JsonDocument u; u["uid"] = lastUid; u["t"] = lastUidAt; String uo; serializeJson(u, uo);
  xSemaphoreTake(lock, portMAX_DELAY); statusCache = out; lastUidCache = uo; xSemaphoreGive(lock);
}

// ---------------- COMMANDS FROM THE DASHBOARD (run in loop) ----------------
void runCommands() {
  xSemaphoreTake(lock, portMAX_DELAY); std::vector<String> todo; todo.swap(commands); xSemaphoreGive(lock);
  for (auto& c : todo) {
    if (c == "reload:cards") loadCards();
    else if (c == "reload:settings") loadSettings();
    else if (c == "reload:timetable") loadTimetable();
    else if (c.startsWith("relay:")) {
      bool on = c.endsWith(":1"); bool light = c.startsWith("relay:light");
      if (light) setLight(on); else setFan(on);
      addLog(String(light ? "Lights" : "Fan") + " switched " + (on ? "ON" : "OFF") + " from dashboard", "green");
    }
    else if (c == "door:open") { openDoor(true); addLog("Door opened from dashboard", "blue"); }
    else if (c == "door:lock") { lockDoor(); addLog("Door locked from dashboard", "blue"); }
    else if (c == "emg:1") startEmergency("Manual alarm from dashboard");
    else if (c == "emg:0") endEmergency();
    else if (c.startsWith("safe:") && emergency) {
      String u = c.substring(5); bool already = false;
      for (auto& s : safeList) if (s == u) already = true;
      if (!already) { safeList.push_back(u); Card* k = findCard(u); addLog("✅ " + (k ? k->name : u) + " marked safe by teacher", "green"); }
    }
    else if (c == "tgtest") telegram("✅ Smart Classroom test message from " + String(CLASS_ID) + ". Alerts are working.");
  }
}

// ---------------- WEB SERVER ----------------
// Collects a POST body (may arrive in several chunks). The library frees _tempObject.
void collectBody(AsyncWebServerRequest* r, uint8_t* data, size_t len, size_t index, size_t total) {
  if (index == 0) { r->_tempObject = malloc(total + 1); if (!r->_tempObject) return; }
  if (!r->_tempObject) return;
  memcpy((uint8_t*)r->_tempObject + index, data, len);
  if (index + len == total) ((char*)r->_tempObject)[total] = 0;
}
String bodyOf(AsyncWebServerRequest* r) { return r->_tempObject ? String((char*)r->_tempObject) : String(); }

void sendJson(AsyncWebServerRequest* r, JsonDocument& doc) {
  String out; serializeJson(doc, out); r->send(200, "application/json", out);
}

// GET returns the file, POST replaces it after checking it is valid JSON
void jsonFileRoute(const char* url, const char* path, const char* fallback, const char* after) {
  server.on(url, HTTP_GET, [path, fallback](AsyncWebServerRequest* r) {
    r->send(200, "application/json", readFile(path, fallback));
  });
  server.on(url, HTTP_POST, [path, after](AsyncWebServerRequest* r) {
    String body = bodyOf(r); JsonDocument test;
    if (body.isEmpty() || deserializeJson(test, body)) { r->send(400, "application/json", "{\"ok\":false}"); return; }
    writeFile(path, body); if (after) pushCommand(after);
    r->send(200, "application/json", "{\"ok\":true}");
  }, nullptr, collectBody);
}

void setupServer() {
  DefaultHeaders::Instance().addHeader("Access-Control-Allow-Origin", "*");
  DefaultHeaders::Instance().addHeader("Access-Control-Allow-Headers", "Content-Type");
  DefaultHeaders::Instance().addHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");

  server.serveStatic("/", LittleFS, "/").setDefaultFile("index.html").setFilter([](AsyncWebServerRequest* r) {
    String u = r->url();                                   // do not expose the data files directly
    return !(u.endsWith(".json") || u.endsWith(".csv"));
  });

  // ---- login ----
  server.on("/api/login", HTTP_POST, [](AsyncWebServerRequest* r) {
    JsonDocument in, out; deserializeJson(in, bodyOf(r));
    String u = in["user"] | "", p = in["pass"] | "";
    out["ok"] = false;
    for (auto& l : LOGINS) if (u == l.user && p == l.pass) { out["ok"] = true; out["role"] = l.role; out["name"] = l.name; }
    sendJson(r, out);
  }, nullptr, collectBody);

  // ---- live status (snapshot made by loop) ----
  server.on("/api/status", HTTP_GET, [](AsyncWebServerRequest* r) {
    String cls = r->hasParam("class") ? r->getParam("class")->value() : CLASS_ID;
    if (cls != CLASS_ID) {     // another room: no sensors here
      r->send(200, "application/json", "{\"session\":{\"active\":false,\"arrivedAt\":0},\"env\":{\"gas\":0,\"motion\":false,\"door\":\"locked\",\"light\":false,\"fan\":false},\"attendance\":{},\"log\":[],\"emergency\":{\"active\":false,\"safe\":[]}}");
      return;
    }
    r->send(200, "application/json", readLocked(statusCache));
  });

  // ---- stored data ----
  jsonFileRoute("/api/classes",   "/classes.json",   "[]", nullptr);
  jsonFileRoute("/api/cards",     "/cards.json",     "[]", "reload:cards");
  jsonFileRoute("/api/timetable", "/timetable.json", "[]", "reload:timetable");
  jsonFileRoute("/api/settings",  "/settings.json",  "{}", "reload:settings");

  // ---- last scanned card (for the "Scan Card" button) ----
  server.on("/api/lastuid", HTTP_GET, [](AsyncWebServerRequest* r) {
    r->send(200, "application/json", readLocked(lastUidCache));
  });

  // ---- controls (executed by loop) ----
  server.on("/api/relay", HTTP_POST, [](AsyncWebServerRequest* r) {
    String dev = r->hasParam("dev") ? r->getParam("dev")->value() : "";
    String st = r->hasParam("state") && r->getParam("state")->value() == "1" ? "1" : "0";
    if (dev == "light" || dev == "fan") pushCommand("relay:" + dev + ":" + st);
    r->send(200, "application/json", "{\"ok\":true}");
  });
  server.on("/api/door", HTTP_POST, [](AsyncWebServerRequest* r) {
    bool open = r->hasParam("action") && r->getParam("action")->value() == "open";
    pushCommand(open ? "door:open" : "door:lock");
    r->send(200, "application/json", "{\"ok\":true}");
  });
  server.on("/api/emergency", HTTP_POST, [](AsyncWebServerRequest* r) {
    bool on = r->hasParam("state") && r->getParam("state")->value() == "1";
    pushCommand(on ? "emg:1" : "emg:0");
    r->send(200, "application/json", "{\"ok\":true}");
  });
  server.on("/api/emergency/safe", HTTP_POST, [](AsyncWebServerRequest* r) {
    if (r->hasParam("uid")) pushCommand("safe:" + r->getParam("uid")->value());
    r->send(200, "application/json", "{\"ok\":true}");
  });
  server.on("/api/telegram/test", HTTP_POST, [](AsyncWebServerRequest* r) {
    pushCommand("tgtest");
    r->send(200, "application/json", "{\"ok\":true}");
  });

  // ---- attendance history (max 31 days to protect memory) ----
  server.on("/api/history", HTTP_GET, [](AsyncWebServerRequest* r) {
    String cls = r->hasParam("class") ? r->getParam("class")->value() : CLASS_ID;
    int days = r->hasParam("days") ? constrain(r->getParam("days")->value().toInt(), 1, 31) : 7;
    time_t from = time(nullptr) - (time_t)days * 86400; struct tm ft; localtime_r(&from, &ft);
    char fromStr[11]; strftime(fromStr, sizeof(fromStr), "%Y-%m-%d", &ft);
    AsyncResponseStream* res = r->beginResponseStream("application/json");
    res->print("[");
    bool first = true;
    File f = LittleFS.open("/history.csv", "r");
    while (f && f.available()) {
      String line = f.readStringUntil('\n'); line.trim();
      int p1 = line.indexOf(','), p2 = line.indexOf(',', p1 + 1), p3 = line.indexOf(',', p2 + 1),
          p4 = line.indexOf(',', p3 + 1), p5 = line.indexOf(',', p4 + 1);
      if (p5 < 0) continue;
      String date = line.substring(0, p1);
      if (date < String(fromStr) || line.substring(p1 + 1, p2) != cls) continue;
      res->printf("%s{\"date\":\"%s\",\"uid\":\"%s\",\"status\":\"%s\",\"lateMin\":%s,\"breaks\":%s}",
        first ? "" : ",", date.c_str(), line.substring(p2 + 1, p3).c_str(), line.substring(p3 + 1, p4).c_str(),
        line.substring(p4 + 1, p5).c_str(), line.substring(p5 + 1).c_str());
      first = false;
    }
    if (f) f.close();
    res->print("]");
    r->send(res);
  });

  server.onNotFound([](AsyncWebServerRequest* r) {
    if (r->method() == HTTP_OPTIONS) r->send(200); else r->send(404, "text/plain", "Not found");
  });
  server.begin();
}

// ---------------- FIREBASE CLOUD SYNC ----------------
// Runs in its own task so slow internet never blocks the RFID reader.
// live/<class>      <- status snapshot every 2 s (the cloud dashboard listens to this)
// commands/<class>  -> dashboard buttons (door, relays, emergency); read and cleared every second
// meta              -> tells the ESP32 when cards / timetable / settings changed
// history/<class>/<date> <- daily attendance for the Reports tab
String fbToken; unsigned long fbTokenAt = 0;

int fbRequest(const String& method, const String& path, const String& body, String* response) {
  WiFiClientSecure client; client.setInsecure();
  HTTPClient http; http.setTimeout(8000);
  String base = FIREBASE_DB_URL; while (base.endsWith("/")) base.remove(base.length() - 1);
  String url = base + "/" + path + ".json?auth=" + fbToken;
  if (!http.begin(client, url)) return -1;
  http.addHeader("Content-Type", "application/json");
  int code = method == "GET" ? http.GET() : http.sendRequest(method.c_str(), body);
  if (response && code > 0) *response = http.getString();
  http.end();
  return code;
}

bool fbSignIn() {
  WiFiClientSecure client; client.setInsecure();
  HTTPClient http;
  String url = String("https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=") + FIREBASE_API_KEY;
  if (!http.begin(client, url)) return false;
  http.addHeader("Content-Type", "application/json");
  JsonDocument b; b["email"] = DEVICE_EMAIL; b["password"] = DEVICE_PASSWORD; b["returnSecureToken"] = true;
  String body; serializeJson(b, body);
  int code = http.POST(body);
  String res = http.getString(); http.end();
  JsonDocument r;
  if (code != 200 || deserializeJson(r, res)) { Serial.printf("Firebase sign-in failed (%d): %s\n", code, res.c_str()); return false; }
  fbToken = r["idToken"] | ""; fbTokenAt = millis();
  Serial.println("Firebase: signed in");
  return fbToken.length() > 0;
}

void syncConfig(const char* node, const char* file, const char* fallback, const char* reloadCmd) {
  String res;
  if (fbRequest("GET", node, "", &res) != 200) return;
  if (res == "null") res = fallback;
  writeFile(file, res);
  pushCommand(reloadCmd);
  Serial.printf("Firebase: %s updated\n", node);
}

void cloudTask(void*) {
  uint64_t seenCards = 0, seenTT = 0, seenSet = 0;
  unsigned long lastLive = 0, lastCmd = 0, lastMeta = 0;
  for (;;) {
    vTaskDelay(pdMS_TO_TICKS(200));
    if (WiFi.status() != WL_CONNECTED) continue;
    if (fbToken.isEmpty() || millis() - fbTokenAt > 50UL * 60UL * 1000UL) {   // tokens last 1 hour
      if (!fbSignIn()) { vTaskDelay(pdMS_TO_TICKS(120000)); continue; }
    }
    String cls = CLASS_ID;

    if (millis() - lastLive > 2000) {                       // push live status
      lastLive = millis();
      int code = fbRequest("PUT", "live/" + cls, readLocked(statusCache), nullptr);
      if (code == 401) fbToken = "";
    }

    if (millis() - lastCmd > 1000) {                        // pull dashboard commands
      lastCmd = millis();
      String res;
      if (fbRequest("GET", "commands/" + cls, "", &res) == 200 && res != "null") {
        JsonDocument d;
        if (!deserializeJson(d, res)) {
          JsonDocument clear;
          for (JsonPair kv : d.as<JsonObject>()) {
            String c = kv.value()["cmd"] | "";
            if (c.length()) pushCommand(c);
            clear[kv.key().c_str()] = nullptr;
          }
          String cs; serializeJson(clear, cs);
          fbRequest("PATCH", "commands/" + cls, cs, nullptr);
        }
      }
    }

    if (millis() - lastMeta > 5000) {                       // did the dashboard change any data?
      lastMeta = millis();
      String res; JsonDocument m;
      if (fbRequest("GET", "meta", "", &res) == 200 && !deserializeJson(m, res)) {
        uint64_t c = m["cardsUpdated"] | 0ULL, t = m["timetableUpdated"] | 0ULL, s = m["settingsUpdated"] | 0ULL;
        if (c != seenCards) { seenCards = c; syncConfig("cards", "/cards.json", "[]", "reload:cards"); }
        if (t != seenTT)    { seenTT = t;    syncConfig("timetable", "/timetable.json", "[]", "reload:timetable"); }
        if (s != seenSet)   { seenSet = s;   syncConfig("settings", "/settings.json", "{}", "reload:settings"); }
      }
    }

    xSemaphoreTake(lock, portMAX_DELAY);                    // upload finished days
    std::vector<String> hist; hist.swap(pendingHistory);
    xSemaphoreGive(lock);
    for (auto& h : hist) {
      int sep = h.indexOf('|');
      fbRequest("PUT", "history/" + cls + "/" + h.substring(0, sep), h.substring(sep + 1), nullptr);
    }
  }
}

// ---------------- SETUP + LOOP ----------------
void setup() {
  Serial.begin(115200);
  lock = xSemaphoreCreateMutex();
  pinMode(PIN_PIR, INPUT); pinMode(PIN_BUZZER, OUTPUT);
  pinMode(PIN_RELAY_LIGHT, OUTPUT); pinMode(PIN_RELAY_FAN, OUTPUT);
  setLight(false); setFan(false);

  Wire.begin(PIN_LCD_SDA, PIN_LCD_SCL);
  lcd.init(); lcd.backlight(); lcdShow("Smart Classroom", "Starting...", 2000);

  ESP32PWM::allocateTimer(0);
  doorServo.setPeriodHertz(50);
  doorServo.attach(PIN_SERVO, 500, 2400);
  lockDoor();

  SPI.begin(PIN_SPI_SCK, PIN_SPI_MISO, PIN_SPI_MOSI, PIN_RFID_SS);
  rfid.PCD_Init(); delay(50); rfid.PCD_DumpVersionToSerial(); rfid.PCD_SetAntennaGain(rfid.RxGain_max);   // 0x91/0x92 = reader OK, 0x00/0xFF = wiring problem

  if (!LittleFS.begin(true)) Serial.println("LittleFS mount failed");
  if (!LittleFS.exists("/index.html")) Serial.println("WARNING: index.html not found. Upload the data folder (see README).");
  if (!LittleFS.exists("/classes.json"))      // first start: create this room so the dashboard has a class
    writeFile("/classes.json", String("[{\"id\":\"") + CLASS_ID + "\",\"name\":\"Grade 10 A\",\"room\":\"Room 12\",\"color\":\"#4f8cff\"}]");
  loadCards(); loadSettings();

  WiFi.mode(WIFI_STA); WiFi.begin(WIFI_SSID, WIFI_PASS);
  Serial.print("Connecting to WiFi");
  while (WiFi.status() != WL_CONNECTED) { delay(400); Serial.print("."); }
  Serial.println("\nConnected. Open this in a browser: http://" + WiFi.localIP().toString());
  lcdShow("Open dashboard:", WiFi.localIP().toString(), 8000);

  configTime(GMT_OFFSET_SEC, 0, "pool.ntp.org", "time.google.com");
  setupServer();
  if (strlen(FIREBASE_API_KEY) && strlen(FIREBASE_DB_URL)) {
    xTaskCreatePinnedToCore(cloudTask, "cloud", 16384, nullptr, 1, nullptr, 0);
    Serial.println("Cloud sync enabled");
  } else Serial.println("Cloud sync off (no Firebase settings). Local dashboard only.");

  Serial.println("Warming up gas sensor...");
  addLog("System started", "blue");
}

void loop() {
  checkNewDay();

  if (rfid.PICC_IsNewCardPresent() && rfid.PICC_ReadCardSerial()) {
    String uid;
    for (byte i = 0; i < rfid.uid.size; i++) {
      if (i) uid += " ";
      if (rfid.uid.uidByte[i] < 0x10) uid += "0";
      uid += String(rfid.uid.uidByte[i], HEX);
    }
    uid.toUpperCase();
    Serial.println("Card: " + uid);
    handleCard(uid);
    rfid.PICC_HaltA(); rfid.PCD_StopCrypto1();
    delay(800);                                   // avoid double reads
  }

  if (doorOpen && doorCloseAtMs && millis() > doorCloseAtMs && !emergency) lockDoor();

  checkSensors();
  runCommands();
  static unsigned long lastSnap = 0;
  if (millis() - lastSnap > 500) { lastSnap = millis(); buildStatus(); }
  sendTelegramQueue();
  sendWhatsAppQueue();
  delay(10);
}