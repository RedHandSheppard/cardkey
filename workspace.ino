#include "M5Cardputer.h"

#include "USB.h"

#include "USBHIDKeyboard.h"

#include <vector>

#include <algorithm>

#include <cstdlib>

#include <ctime>

#include <SD.h>

#include <SPI.h>

#include <AES.h>

#include <CBC.h>

#include <SHA256.h>

#include <esp_system.h>

#include "mbedtls/pkcs5.h"

#include "mbedtls/md.h"

#define SD_SPI_SCK_PIN 40

#define SD_SPI_MISO_PIN 39

#define SD_SPI_MOSI_PIN 14

#define SD_SPI_CS_PIN 12

#define KEY_DELETE 76

#define KEY_UP_ARROW 0x52

#define KEY_DOWN_ARROW 0x51

#define KEY_LEFT_ARROW 0x50

#define KEY_RIGHT_ARROW 0x4F

#define KEY_ESC 0x29

#define KEY_BACKSPACE_HID 0x2a

#define KEY_ENTER_HID 0x28

#define KEY_SEMICOLON_HID 0x33

#define KEY_PERIOD_HID 0x37

#define KEY_COMMA_HID 0x36

#define KEY_SLASH_HID 0x38

#define KEY_BACKTICK_HID 0x35

#define KEY_MOD_LSHIFT 0x02

#define KEY_MOD_RSHIFT 0x20

USBHIDKeyboard Keyboard;

enum State {

STATE_KEYBOARD,

STATE_PROMPT,

STATE_TOP_MENU,

STATE_PASS_MENU,

STATE_PASS_EDIT_MENU,

STATE_NOTE_MENU,

STATE_CHANGE_MASTER,

STATE_NOTE_EDIT,

STATE_NOTE_BODY_EDIT,

STATE_COLOR_MENU

};

State currentState = STATE_KEYBOARD;

const int BUTTON_HEIGHT = 20;

const int MAX_VISIBLE_BUTTONS = 6;

String MASTER_PASSWORD = "m5pass";

uint8_t CURRENT_SALT[16] = {0};

const unsigned long FN_CTRL_DEBOUNCE_MS = 500;

const uint32_t MENU_TIMEOUT_MS = 15000;

const uint32_t KEY_REPEAT_DELAY_MS = 500;

const uint32_t KEY_REPEAT_RATE_MS = 75;

const char* SD_VAULT_FILE_PATH = "/vault.txt";

const char* SD_CONFIG_FILE_PATH = "/config.txt";

const size_t AES_KEY_SIZE = 32;

const size_t AES_BLOCK_SIZE = 16;

const size_t HMAC_TAG_SIZE = SHA256::HASH_SIZE;

const size_t PBKDF2_ITERATIONS = 37000;

uint8_t IV[AES_BLOCK_SIZE] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};

struct PasswordEntry {

String label;

String username;

String password;

};

struct NoteEntry {

String label;

String body;

};

struct MenuEntry {

String label;

State targetState;

void (*action)();

};

M5Canvas canvas(&M5Cardputer.Display);

uint16_t MENU_HIGHLIGHT_COLOR = RED;

uint16_t hexToRGB565(String hexColor) {

if (hexColor.length() != 6) return 0;

unsigned long color888 = strtoul(hexColor.c_str(), NULL, 16);

uint8_t r8 = (color888 >> 16) & 0xFF;

uint8_t g8 = (color888 >> 8) & 0xFF;

uint8_t b8 = color888 & 0xFF;

uint16_t r5 = r8 >> 3;

uint16_t g6 = g8 >> 2;

uint16_t b5 = b8 >> 3;

return (r5 << 11) | (g6 << 5) | b5;

}

void RGB565toRGB888(uint16_t color565, uint8_t &r8, uint8_t &g8, uint8_t &b8) {

uint8_t r5 = (color565 >> 11) & 0x1F;

uint8_t g6 = (color565 >> 5) & 0x3F;

uint8_t b5 = color565 & 0x1F;

r8 = (r5 * 527 + 23) >> 6;

g8 = (g6 * 259 + 33) >> 6;

b8 = (b5 * 527 + 23) >> 6;

}

uint16_t getContrastColor(uint16_t color) {

uint8_t r8, g8, b8;

RGB565toRGB888(color, r8, g8, b8);

unsigned long luminance = (r8 * 54) + (g8 * 183) + (b8 * 18);

if (luminance < 28000) {

return WHITE;

} else {

return BLACK;

}

}

std::vector<MenuEntry> TopMenuItems = {

{"!! New Vault Pass !!", STATE_CHANGE_MASTER, nullptr},

{"-> New Menu Color <-", STATE_COLOR_MENU, nullptr},

{"-> Notes <-", STATE_NOTE_MENU, nullptr},

{"-> Passwords <-", STATE_PASS_MENU, nullptr},

};

struct ColorEntry {

String name;

uint16_t color;

bool isAction;

};

std::vector<ColorEntry> ColorMenuItems = {

{"<- MAIN/Colors", BLACK, true},

{"HEX COLOR", BLACK, true},

{"RED", RED, false},

{"YELLOW", YELLOW, false},

{"BLUE", BLUE, false},

{"GREEN", GREEN, false},

{"ORANGE", ORANGE, false},

{"PURPLE", TFT_MAGENTA, false}

};

std::vector<PasswordEntry> PassEntries;

std::vector<NoteEntry> NoteEntries;

std::vector<String> PassMenuDisplayItems;

std::vector<String> NoteMenuDisplayItems;

int SelectedMenuIndex = 0;

int PassDataIndex = 0;

int currentEditIndex = -1;

int visibleOffset = 0;

unsigned long lastFnCtrlTime = 0;

bool isSDInitialized = false;

CBC<AES256> aes_cbc;

SHA256 sha256_hmac;

String ENCRYPTED_VAULT_STRING = "";

unsigned long lastActivityTime = 0;

unsigned long lastKeyPressTime = 0;

unsigned long lastKeyRepeatTime = 0;

uint8_t repeatingKey = 0;

std::vector<uint8_t> currentPressedKeys;

int cursorPos = 0;

int bodyScrollOffset = 0;

void drawPromptScreen(const char* title, const String& input_masked, const char* status_msg);

void drawMenuList(const std::vector<String>& items, int selectedIndex);

void drawTopMenu();

void drawPassMenu();

void drawPassEditMenu();

void drawNoteMenu();

void drawNoteEditMenu();

void drawNoteBodyEditScreen(const String& currentBody, int cursor_pos, int scroll_offset);

void drawColorMenu();

void runKeyboard();

void runPrompt();

void runTopMenu();

void runPassMenu();

void runNoteMenu();

void runPassEditMenu();

void runNoteEditMenu();

void runNoteBodyEditScreen();

void runChangeMaster();

void runColorMenu();

bool handleMenuAction(State currentState, int selectedIndex);

bool handleMenuNavigation(const std::vector<String>& items, int& selectedIndex, void (*drawFunction)());

void buildPassMenuDisplayItems();

void buildNoteMenuDisplayItems();

String getEntryInput(const char* prompt);

String getPasswordInput(const char* prompt, const String& expected_password = "");

bool checkForUniversalExit();

void sendEntryOverUSB(const String& data);

void timeoutToKeyboard();

void startMenuTimer();

void resetMenuTimer();

void playBeep(int freq, int duration);

void generateRandomSalt(uint8_t* salt_out);

void deriveKey(const String& masterPass, const uint8_t* salt, uint8_t* key_out);

String encryptAES(const String& data, const String& masterPass, const uint8_t* salt);

String decryptAES(const String& encryptedData, const String& masterPass);

void initializeVaultFile();

bool saveData();

bool loadEncryptedData();

bool saveConfigData();

void loadConfigData();

String generateStrongPassword();

void setup() {

auto cfg = M5.config();

M5Cardputer.Display.setBrightness(0);

M5Cardputer.Display.clear();

M5Cardputer.begin(cfg);

pinMode(1, INPUT);

long randomSeedValue = analogRead(1);

srand(randomSeedValue);

Keyboard.begin();

USB.begin();

canvas.createSprite(M5Cardputer.Display.width(), M5Cardputer.Display.height());

canvas.setTextFont(&fonts::FreeMonoBold12pt7b);

canvas.setTextSize(0.8);

SPI.begin(SD_SPI_SCK_PIN, SD_SPI_MISO_PIN, SD_SPI_MOSI_PIN, -1);

if(SD.begin(SD_SPI_CS_PIN, SPI, 25000000)) {

isSDInitialized = true;

} else {

isSDInitialized = false;

}

if (isSDInitialized) {

initializeVaultFile();

loadConfigData();

}

playBeep(1000, 50);

if (isSDInitialized) {

delay(200);

playBeep(1500, 50);

}

currentState = STATE_KEYBOARD;

}

void loop() {

M5Cardputer.update();

if (currentState != STATE_KEYBOARD && (millis() - lastActivityTime >= MENU_TIMEOUT_MS)) {

timeoutToKeyboard();

}

switch (currentState) {

case STATE_KEYBOARD:

runKeyboard();

break;

case STATE_PROMPT:

runPrompt();

break;

case STATE_TOP_MENU:

runTopMenu();

break;

case STATE_PASS_MENU:

runPassMenu();

break;

case STATE_NOTE_MENU:

runNoteMenu();

break;

case STATE_PASS_EDIT_MENU:

runPassEditMenu();

break;

case STATE_NOTE_EDIT:

runNoteEditMenu();

break;

case STATE_NOTE_BODY_EDIT:

runNoteBodyEditScreen();

break;

case STATE_CHANGE_MASTER:

runChangeMaster();

break;

case STATE_COLOR_MENU:

runColorMenu();

break;

}

}

void timeoutToKeyboard() {

if (currentState != STATE_KEYBOARD) {

M5Cardputer.Display.clear();

M5Cardputer.Display.setBrightness(0);

currentState = STATE_KEYBOARD;

repeatingKey = 0;

currentPressedKeys.clear();

}

}

void startMenuTimer() {

lastActivityTime = millis();

}

void resetMenuTimer() {

lastActivityTime = millis();

}

void playBeep(int freq, int duration) {

M5Cardputer.Speaker.tone(freq, duration);

delay(duration);

}

void sendEntryOverUSB(const String& data) {

Keyboard.print(data);

delay(50);

}

bool checkForUniversalExit() {

if ((currentState != STATE_KEYBOARD) &&

(millis() - lastFnCtrlTime < 200)) {

return false;

}

if (M5Cardputer.Keyboard.isKeyPressed(KEY_FN) &&

M5Cardputer.Keyboard.isKeyPressed(KEY_LEFT_CTRL) &&

(millis() - lastFnCtrlTime > FN_CTRL_DEBOUNCE_MS)) {

lastFnCtrlTime = millis();

M5Cardputer.Display.clear();

M5Cardputer.Display.setBrightness(0);

currentState = STATE_KEYBOARD;

repeatingKey = 0;

currentPressedKeys.clear();

return true;

}

return false;

}

void drawPromptScreen(const char* title, const String& input_masked, const char* status_msg) {

canvas.fillScreen(BLACK);

canvas.setTextFont(&fonts::FreeMonoBold12pt7b);

canvas.setTextSize(0.8);

canvas.setTextColor(MENU_HIGHLIGHT_COLOR, BLACK);

int titleWidth = canvas.textWidth(title);

int titleX = (canvas.width() - titleWidth) / 2;

canvas.drawString(title, titleX, 30);

canvas.setTextSize(1.0);

canvas.setTextColor(MENU_HIGHLIGHT_COLOR, BLACK);

int inputWidth = canvas.textWidth(input_masked);

int inputX = (canvas.width() - inputWidth) / 2;

canvas.drawString(input_masked, inputX, 70);

if (strlen(status_msg) > 0) {

canvas.setTextSize(1.0);

canvas.setTextColor(MENU_HIGHLIGHT_COLOR, BLACK);

int statusWidth = canvas.textWidth(status_msg);

int statusX = (canvas.width() - statusWidth) / 2;

canvas.drawString(status_msg, statusX, 110);

}

canvas.pushSprite(0, 0);

}

void drawMenuList(const std::vector<String>& items, int selectedIndex) {

canvas.fillScreen(BLACK);

canvas.setTextFont(&fonts::FreeMonoBold12pt7b);

canvas.setTextSize(0.8);

int startY = 0;

for (int i = 0; i < MAX_VISIBLE_BUTTONS; i++) {

int itemIndex = i + visibleOffset;

if (itemIndex >= items.size()) {

break;

}

int yPos = startY + i * BUTTON_HEIGHT;

if (itemIndex == selectedIndex) {

canvas.fillRect(0, yPos, canvas.width(), BUTTON_HEIGHT, MENU_HIGHLIGHT_COLOR);

uint16_t text_color = getContrastColor(MENU_HIGHLIGHT_COLOR);

canvas.setTextColor(text_color, MENU_HIGHLIGHT_COLOR);

} else {

if (items[itemIndex].startsWith("!!") || items[itemIndex].startsWith("<-") || items[itemIndex].startsWith("->")) {

canvas.setTextColor(MENU_HIGHLIGHT_COLOR, BLACK);

} else {

canvas.setTextColor(WHITE, BLACK);

}

}

canvas.drawString(items[itemIndex], 5, yPos + 3);

}

canvas.pushSprite(0, 0);

}

void drawTopMenu() {

std::vector<String> labels;

for (const auto& entry : TopMenuItems) {

labels.push_back(entry.label);

}

canvas.fillScreen(BLACK);

canvas.setTextFont(&fonts::FreeMonoBold12pt7b);

canvas.setTextSize(0.8);

int startY = 0;

for (int i = 0; i < MAX_VISIBLE_BUTTONS; i++) {

int itemIndex = i + visibleOffset;

if (itemIndex >= labels.size()) {

break;

}

int yPos = startY + i * BUTTON_HEIGHT;

if (itemIndex == SelectedMenuIndex) {

canvas.fillRect(0, yPos, canvas.width(), BUTTON_HEIGHT, MENU_HIGHLIGHT_COLOR);

uint16_t text_color = getContrastColor(MENU_HIGHLIGHT_COLOR);

canvas.setTextColor(text_color, MENU_HIGHLIGHT_COLOR);

} else {

if (labels[itemIndex].startsWith("!!") || labels[itemIndex] == "-> New Menu Color <-") {

canvas.setTextColor(MENU_HIGHLIGHT_COLOR, BLACK);

} else {

canvas.setTextColor(WHITE, BLACK);

}

}

canvas.drawString(labels[itemIndex], 5, yPos + 3);

}

canvas.pushSprite(0, 0);

}

void drawPassMenu() {

drawMenuList(PassMenuDisplayItems, SelectedMenuIndex);

}

void drawNoteMenu() {

buildNoteMenuDisplayItems();

drawMenuList(NoteMenuDisplayItems, SelectedMenuIndex);

}

void drawColorMenu() {

canvas.fillScreen(BLACK);

canvas.setTextFont(&fonts::FreeMonoBold12pt7b);

canvas.setTextSize(0.8);

int startY = 0;

for (int i = 0; i < MAX_VISIBLE_BUTTONS; i++) {

int itemIndex = i + visibleOffset;

if (itemIndex >= ColorMenuItems.size()) {

break;

}

const ColorEntry& currentEntry = ColorMenuItems[itemIndex];

int yPos = startY + i * BUTTON_HEIGHT;

uint16_t item_color = currentEntry.color;

String display_label = currentEntry.name;

bool is_action = currentEntry.isAction;

if (itemIndex == 1) { 

    char hex_code[5];
    sprintf(hex_code, "%04X", MENU_HIGHLIGHT_COLOR); 
    display_label = display_label + " (0x" + String(hex_code) + ")";

} else if (!is_action) {

display_label = "SET TO: " + display_label;

}

if (itemIndex == SelectedMenuIndex) {

canvas.fillRect(0, yPos, canvas.width(), BUTTON_HEIGHT, MENU_HIGHLIGHT_COLOR);

uint16_t text_color = getContrastColor(MENU_HIGHLIGHT_COLOR);

canvas.setTextColor(text_color, MENU_HIGHLIGHT_COLOR);

} else {

if (itemIndex == 0) {

canvas.setTextColor(MENU_HIGHLIGHT_COLOR, BLACK);

} else if (!is_action) {

canvas.setTextColor(item_color, BLACK);

} else {

canvas.setTextColor(WHITE, BLACK);

}

}

canvas.drawString(display_label, 5, yPos + 3);

}

canvas.pushSprite(0, 0);

}

void drawPassEditMenu() {

canvas.fillScreen(BLACK);

canvas.setTextFont(&fonts::FreeMonoBold12pt7b);

canvas.setTextSize(0.8);

if (currentEditIndex < 0 || currentEditIndex >= PassEntries.size()) {

canvas.drawString("ERROR: Invalid Index", 10, 10);

canvas.pushSprite(0, 0);

return;

}

PasswordEntry& entry = PassEntries[currentEditIndex];

String fields[] = {

"<- Main/Pass/Edit",

"LABEL: " + entry.label,

"USER: " + entry.username,

"PASS: " + entry.password,

"!! GENERATE PASS !!",

"!! DELETE ENTRY !!"

};

for (int i = 0; i < 6; i++) {

int yPos = i * BUTTON_HEIGHT;

bool is_special_option = (i == 0 || i == 4 || i == 5);

if (i == PassDataIndex) {

canvas.fillRect(0, yPos, canvas.width(), BUTTON_HEIGHT, MENU_HIGHLIGHT_COLOR);

uint16_t text_color = getContrastColor(MENU_HIGHLIGHT_COLOR);

canvas.setTextColor(text_color, MENU_HIGHLIGHT_COLOR);

} else {

if (is_special_option) {

canvas.setTextColor(MENU_HIGHLIGHT_COLOR, BLACK);

} else {

canvas.setTextColor(WHITE, BLACK);

}

}

canvas.drawString(fields[i], 5, yPos + 3);

}

canvas.pushSprite(0, 0);

}

void drawNoteEditMenu() {

canvas.fillScreen(BLACK);

canvas.setTextFont(&fonts::FreeMonoBold12pt7b);

canvas.setTextSize(0.8);

if (currentEditIndex < 0 || currentEditIndex >= NoteEntries.size()) {

canvas.drawString("ERROR: Invalid Index", 10, 10);

canvas.pushSprite(0, 0);

return;

}

NoteEntry& entry = NoteEntries[currentEditIndex];

String bodyPreview = entry.body.substring(0, min((int)entry.body.length(), 40));

bodyPreview.replace('\n', ' ');

if (entry.body.length() > 40) {

bodyPreview += "...";

}

if (bodyPreview.length() == 0) {

bodyPreview = "(Empty Note)";

}

String fields[] = {

"<- Main/Note/Edit",

"TITLE: " + entry.label,

"BODY: " + bodyPreview,

"!! DELETE ENTRY !!"

};

for (int i = 0; i < 4; i++) {

int yPos = i * BUTTON_HEIGHT;

bool is_special_option = (i == 0 || i == 3);

if (i == PassDataIndex) {

canvas.fillRect(0, yPos, canvas.width(), BUTTON_HEIGHT, MENU_HIGHLIGHT_COLOR);

uint16_t text_color = getContrastColor(MENU_HIGHLIGHT_COLOR);

canvas.setTextColor(text_color, MENU_HIGHLIGHT_COLOR);

} else {

if (is_special_option) {

canvas.setTextColor(MENU_HIGHLIGHT_COLOR, BLACK);

} else {

canvas.setTextColor(WHITE, BLACK);

}

}

canvas.drawString(fields[i], 5, yPos + 3);

}

canvas.pushSprite(0, 0);

}

void drawNoteBodyEditScreen(const String& currentBody, int cursor_pos, int scroll_offset) {

canvas.fillScreen(BLACK);

canvas.setTextFont(&fonts::FreeMonoBold12pt7b);

canvas.setTextSize(0.8);

canvas.setTextColor(WHITE, BLACK);

int startY = 0;

int lineHeight = 15;

int maxLines = canvas.height() / lineHeight;

std::vector<int> lineStarts;

std::vector<int> lineLengths;

int currentPos = 0;

if (currentBody.length() == 0) {

lineStarts.push_back(0);

lineLengths.push_back(0);

} else {

do {

int nextPos = currentBody.indexOf('\n', currentPos);

lineStarts.push_back(currentPos);

if (nextPos == -1) {

lineLengths.push_back(currentBody.length() - currentPos);

currentPos = currentBody.length();

} else {

lineLengths.push_back(nextPos - currentPos);

currentPos = nextPos + 1;

}

} while (currentPos < currentBody.length());

if (currentBody.length() > 0 && currentBody[currentBody.length() - 1] == '\n') {

lineStarts.push_back(currentBody.length());

lineLengths.push_back(0);

}

}

int cursorLineIndex = 0;

for (size_t i = 0; i < lineStarts.size(); ++i) {

if (cursor_pos >= lineStarts[i] &&

(i == lineStarts.size() - 1 || cursor_pos < lineStarts[i + 1])) {

cursorLineIndex = i;

break;

}

}

if (cursorLineIndex < scroll_offset) {

scroll_offset = cursorLineIndex;

} else if (cursorLineIndex >= scroll_offset + maxLines) {

scroll_offset = cursorLineIndex - maxLines + 1;

}

bodyScrollOffset = scroll_offset;

for (int i = 0; i < maxLines; i++) {

int lineIndex = i + bodyScrollOffset;

if (lineIndex < lineStarts.size()) {

int start = lineStarts[lineIndex];

int length = lineLengths[lineIndex];

String line = currentBody.substring(start, start + length);

canvas.drawString(line, 5, startY + i * lineHeight);

if (lineIndex == cursorLineIndex) {

int charOffset = cursor_pos - start;

String textBeforeCursor = line.substring(0, charOffset);

int cursorX = 5 + canvas.textWidth(textBeforeCursor);

if ((millis() / 500) % 2 == 0) {

canvas.drawFastVLine(cursorX, startY + i * lineHeight, lineHeight - 2, TFT_WHITE);

}

}

}

}

canvas.pushSprite(0, 0);

}

void buildPassMenuDisplayItems() {

PassMenuDisplayItems.clear();

PassMenuDisplayItems.push_back("<- MAIN/Passwords");

for (const auto& entry : PassEntries) {

PassMenuDisplayItems.push_back(entry.label);

}

PassMenuDisplayItems.push_back("-> ADD ENTRY <-");

}

void buildNoteMenuDisplayItems() {

NoteMenuDisplayItems.clear();

NoteMenuDisplayItems.push_back("<- MAIN/Notes");

for (const auto& entry : NoteEntries) {

NoteMenuDisplayItems.push_back(entry.label);

}

NoteMenuDisplayItems.push_back("-> ADD NOTE <-");

}

bool handleMenuAction(State state, int index) {

if (state == STATE_TOP_MENU) {

if (index < TopMenuItems.size()) {

State target = TopMenuItems[index].targetState;

SelectedMenuIndex = 0;

visibleOffset = 0;

if (target == STATE_CHANGE_MASTER) {

currentState = STATE_CHANGE_MASTER;

} else if (target == STATE_PASS_MENU) {

buildPassMenuDisplayItems();

currentState = STATE_PASS_MENU;

drawPassMenu();

} else if (target == STATE_NOTE_MENU) {

buildNoteMenuDisplayItems();

currentState = STATE_NOTE_MENU;

drawNoteMenu();

} else if (target == STATE_COLOR_MENU) {

SelectedMenuIndex = 0;

visibleOffset = 0;

currentState = STATE_COLOR_MENU;

drawColorMenu();

}

resetMenuTimer();

return true;

}

}

else if (state == STATE_COLOR_MENU) {

const ColorEntry& selectedEntry = ColorMenuItems[index];

if (index == 0) {

currentState = STATE_TOP_MENU;

drawTopMenu();

resetMenuTimer();

return true;

} else if (index == 1) {

String hexInput = getEntryInput("Enter 6-digit Hex (RRGGBB):");

if (currentState == STATE_KEYBOARD) return true;

hexInput.toUpperCase();

if (hexInput.length() == 6) {

bool valid = true;

for (int i = 0; i < 6; i++) {

if (!isxdigit(hexInput[i])) {

valid = false;

break;

}

}

if (valid) {

MENU_HIGHLIGHT_COLOR = hexToRGB565(hexInput);

saveConfigData();

drawPromptScreen("Color Saved!", "", "");

delay(800);

} else {

drawPromptScreen("Invalid Hex", "", "");

delay(800);

}

} else {

drawPromptScreen("Must be 6 digits", "", "");

delay(800);

}

if (currentState != STATE_KEYBOARD) {

drawColorMenu();

resetMenuTimer();

}

return true;

} else {

MENU_HIGHLIGHT_COLOR = selectedEntry.color;

saveConfigData();

String successMsg = selectedEntry.name + " Set & Saved!";

drawPromptScreen("SUCCESS", "", successMsg.c_str());

delay(800);

drawColorMenu();

resetMenuTimer();

return true;

}

}

else if (state == STATE_PASS_MENU) {

if (index == 0) {

currentState = STATE_TOP_MENU;

drawTopMenu();

resetMenuTimer();

return true;

} else if (index == PassMenuDisplayItems.size() - 1) {

String label = getEntryInput("Enter Label:");

if (currentState == STATE_KEYBOARD) return true;

if (label.length() > 0) {

String user = getEntryInput("Enter Username:");

if (currentState == STATE_KEYBOARD) return true;

String pass = getEntryInput("Enter Password");

if (currentState == STATE_KEYBOARD) return true;

if (pass.length() == 0) {

pass = generateStrongPassword();

}

PasswordEntry newEntry = {label, user, pass};

PassEntries.push_back(newEntry);

if (!saveData()) {

drawPromptScreen("Save Failed!", "", "");

delay(1000);

PassEntries.pop_back();

} else {

buildPassMenuDisplayItems();

SelectedMenuIndex = PassMenuDisplayItems.size() - 2;

if (SelectedMenuIndex >= visibleOffset + MAX_VISIBLE_BUTTONS) {

visibleOffset = SelectedMenuIndex - MAX_VISIBLE_BUTTONS + 1;

}

}

}

if (currentState != STATE_KEYBOARD) {

drawPassMenu();

resetMenuTimer();

}

return true;

} else {

currentEditIndex = index - 1;

PassDataIndex = 1;

currentState = STATE_PASS_EDIT_MENU;

drawPassEditMenu();

resetMenuTimer();

return true;

}

}

else if (state == STATE_NOTE_MENU) {

if (index == 0) {

currentState = STATE_TOP_MENU;

drawTopMenu();

resetMenuTimer();

return true;

} else if (index == NoteMenuDisplayItems.size() - 1) {

String label = getEntryInput("Enter Title:");

if (currentState == STATE_KEYBOARD) return true;

if (label.length() > 0) {

NoteEntry newEntry = {label, ""};

NoteEntries.push_back(newEntry);

if (!saveData()) {

drawPromptScreen("Save Failed!", "", "");

delay(1000);

NoteEntries.pop_back();

} else {

buildNoteMenuDisplayItems();

SelectedMenuIndex = NoteMenuDisplayItems.size() - 2;

}

}

if (currentState != STATE_KEYBOARD) {

drawNoteMenu();

resetMenuTimer();

}

return true;

} else {

currentEditIndex = index - 1;

PassDataIndex = 1;

currentState = STATE_NOTE_EDIT;

drawNoteEditMenu();

resetMenuTimer();

return true;

}

}

return false;

}

bool handleMenuNavigation(const std::vector<String>& items, int& selectedIndex, void (*drawFunction)()) {

if (!M5Cardputer.Keyboard.isChange()) {

return false;

}

resetMenuTimer();

Keyboard_Class::KeysState status = M5Cardputer.Keyboard.keysState();

bool is_up_pressed = status.fn && (std::find(status.hid_keys.begin(), status.hid_keys.end(), KEY_SEMICOLON_HID) != status.hid_keys.end());

bool is_down_pressed = status.fn && (std::find(status.hid_keys.begin(), status.hid_keys.end(), KEY_PERIOD_HID) != status.hid_keys.end());

bool is_enter_pressed = status.enter;

if (is_up_pressed || is_down_pressed) {

if (is_up_pressed) {

if (selectedIndex > 0) {

selectedIndex--;

if (selectedIndex < visibleOffset) {

visibleOffset = selectedIndex;

}

drawFunction();

delay(150);

}

} else {

if (selectedIndex < items.size() - 1) {

selectedIndex++;

if (selectedIndex >= visibleOffset + MAX_VISIBLE_BUTTONS) {

visibleOffset++;

}

drawFunction();

delay(150);

}

}

}

else if (is_enter_pressed) {

handleMenuAction(currentState, selectedIndex);

delay(150);

}

return true;

}

void runKeyboard() {

Keyboard_Class::KeysState status = M5Cardputer.Keyboard.keysState();

unsigned long currentMillis = millis();

if (isSDInitialized) {

if (M5Cardputer.Keyboard.isKeyPressed(KEY_FN) &&

M5Cardputer.Keyboard.isKeyPressed(KEY_LEFT_CTRL) &&

(currentMillis - lastFnCtrlTime > FN_CTRL_DEBOUNCE_MS)) {

lastFnCtrlTime = currentMillis;

M5Cardputer.Display.clear();

M5Cardputer.Display.setBrightness(100);

loadEncryptedData();

repeatingKey = 0;

currentPressedKeys.clear();

currentState = STATE_PROMPT;

startMenuTimer();

return;

}

}

bool keySetChanged = false;

if (status.hid_keys.size() != currentPressedKeys.size()) {

keySetChanged = true;

} else {

std::vector<uint8_t> status_keys_sorted = status.hid_keys;

std::vector<uint8_t> current_keys_sorted = currentPressedKeys;

std::sort(status_keys_sorted.begin(), status_keys_sorted.end());

std::sort(current_keys_sorted.begin(), current_keys_sorted.end());

if (status_keys_sorted.size() == current_keys_sorted.size() &&

!std::equal(status_keys_sorted.begin(), status_keys_sorted.end(), current_keys_sorted.begin())) {

keySetChanged = true;

}

}

if (keySetChanged) {

currentPressedKeys.clear();

for(uint8_t key_code : status.hid_keys) {

currentPressedKeys.push_back(key_code);

}

KeyReport report = {0};

report.modifiers = status.modifiers;

uint8_t index = 0;

for (auto i : status.hid_keys) {

report.keys[index] = i;

index++;

if (index > 5) break;

}

bool isFnCombo = false;

uint8_t virtualKey = 0;

if (M5Cardputer.Keyboard.isKeyPressed(KEY_FN) && status.modifiers == 0) {

if (status.hid_keys.size() == 1) {

uint8_t key_code = status.hid_keys[0];

if (key_code == KEY_BACKSPACE_HID) { virtualKey = KEY_DELETE; isFnCombo = true; }

else if (key_code == KEY_COMMA_HID) { virtualKey = KEY_LEFT_ARROW; isFnCombo = true; }

else if (key_code == KEY_SEMICOLON_HID) { virtualKey = KEY_UP_ARROW; isFnCombo = true; }

else if (key_code == KEY_PERIOD_HID) { virtualKey = KEY_DOWN_ARROW; isFnCombo = true; }

else if (key_code == KEY_SLASH_HID) { virtualKey = KEY_RIGHT_ARROW; isFnCombo = true; }

else if (key_code == KEY_BACKTICK_HID) { virtualKey = KEY_ESC; isFnCombo = true; }

}

if (isFnCombo) {

KeyReport fnReport = {0};

fnReport.keys[0] = virtualKey;

Keyboard.sendReport(&fnReport);

Keyboard.releaseAll();

}

}

if (!isFnCombo) {

Keyboard.sendReport(&report);

if (report.modifiers != 0 || report.keys[0] != 0) {

Keyboard.releaseAll();

}

}

uint8_t newRepeatingKey = 0;

if (status.hid_keys.size() == 1) {

if (status.modifiers == 0 || status.modifiers == KEY_MOD_LSHIFT || status.modifiers == KEY_MOD_RSHIFT) {

newRepeatingKey = status.hid_keys[0];

}

}

else if (M5Cardputer.Keyboard.isKeyPressed(KEY_FN) && status.modifiers == 0) {

if (status.hid_keys.size() == 1) {

uint8_t key_code = status.hid_keys[0];

if (key_code == KEY_BACKSPACE_HID) { newRepeatingKey = KEY_DELETE; }

else if (key_code == KEY_COMMA_HID) { newRepeatingKey = KEY_LEFT_ARROW; }

else if (key_code == KEY_SEMICOLON_HID) { newRepeatingKey = KEY_UP_ARROW; }

else if (key_code == KEY_PERIOD_HID) { newRepeatingKey = KEY_DOWN_ARROW; }

else if (key_code == KEY_SLASH_HID) { newRepeatingKey = KEY_RIGHT_ARROW; }

}

}

else if (status.hid_keys.size() > 1 && (status.modifiers & ~KEY_MOD_LSHIFT & ~KEY_MOD_RSHIFT) != 0) {

if (std::find(status.hid_keys.begin(), status.hid_keys.end(), KEY_BACKSPACE_HID) != status.hid_keys.end()) {

newRepeatingKey = KEY_BACKSPACE_HID;

}

}

if (newRepeatingKey != repeatingKey) {

repeatingKey = newRepeatingKey;

if (repeatingKey != 0) {

lastKeyPressTime = currentMillis;

lastKeyRepeatTime = currentMillis;

} else {

lastKeyPressTime = 0;

}

}

}

if (repeatingKey != 0) {

if (currentMillis - lastKeyPressTime >= KEY_REPEAT_DELAY_MS) {

if (currentMillis - lastKeyRepeatTime >= KEY_REPEAT_RATE_MS) {

KeyReport repeatReport = {0};

uint8_t repeatKeyToSend = repeatingKey;

uint8_t repeatModifiers = M5Cardputer.Keyboard.keysState().modifiers;

if (M5Cardputer.Keyboard.isKeyPressed(KEY_FN) && repeatModifiers == 0) {

if (repeatingKey == KEY_DELETE) repeatKeyToSend = KEY_DELETE;

else if (repeatingKey == KEY_LEFT_ARROW) repeatKeyToSend = KEY_LEFT_ARROW;

else if (repeatingKey == KEY_UP_ARROW) repeatKeyToSend = KEY_UP_ARROW;

else if (repeatingKey == KEY_DOWN_ARROW) repeatKeyToSend = KEY_DOWN_ARROW;

else if (repeatingKey == KEY_RIGHT_ARROW) repeatKeyToSend = KEY_RIGHT_ARROW;

} else if (repeatingKey == KEY_BACKSPACE_HID) {

repeatKeyToSend = KEY_BACKSPACE_HID;

}

repeatReport.keys[0] = repeatKeyToSend;

repeatReport.modifiers = repeatModifiers;

Keyboard.sendReport(&repeatReport);

Keyboard.releaseAll();

lastKeyRepeatTime = currentMillis;

}

}

}

}

void runPrompt() {

if (checkForUniversalExit()) return;

const char* prompt_msg = "ENTER PASSWORD";

String input = getPasswordInput(prompt_msg);

if (currentState == STATE_KEYBOARD) {

return;

}

if (input.length() > 0) {

if (ENCRYPTED_VAULT_STRING.length() == 0) {

loadEncryptedData();

}

String decryptedData = "";

if (ENCRYPTED_VAULT_STRING.length() > 0) {

decryptedData = decryptAES(ENCRYPTED_VAULT_STRING, input);

}

if (decryptedData.length() > 0) {

PassEntries.clear();

NoteEntries.clear();

int masterEnd = decryptedData.indexOf("@@@");

int passEnd = decryptedData.indexOf("@@@", masterEnd + 3);

if (masterEnd == -1) {

MASTER_PASSWORD = decryptedData;

} else {

MASTER_PASSWORD = decryptedData.substring(0, masterEnd);

String entriesString = decryptedData.substring(masterEnd + 3, passEnd);

int currentPos = 0;

while(currentPos < entriesString.length()) {

int entryEnd = entriesString.indexOf('|', currentPos);

if (entryEnd == -1) entryEnd = entriesString.length();

String entry = entriesString.substring(currentPos, entryEnd);

int labelEnd = entry.indexOf(',');

int userEnd = entry.indexOf(',', labelEnd + 1);

if (labelEnd != -1 && userEnd != -1) {

PasswordEntry newEntry;

newEntry.label = entry.substring(0, labelEnd);

newEntry.username = entry.substring(labelEnd + 1, userEnd);

newEntry.password = entry.substring(userEnd + 1);

PassEntries.push_back(newEntry);

}

currentPos = entryEnd + 1;

if (entryEnd == entriesString.length()) break;

}

String noteString = decryptedData.substring(passEnd + 3);

currentPos = 0;

while(currentPos < noteString.length()) {

int entryEnd = noteString.indexOf('|', currentPos);

if (entryEnd == -1) entryEnd = noteString.length();

String entry = noteString.substring(currentPos, entryEnd);

int labelEnd = entry.indexOf(',');

if (labelEnd != -1) {

NoteEntry newEntry;

newEntry.label = entry.substring(0, labelEnd);

newEntry.body = entry.substring(labelEnd + 1);

newEntry.body.replace("###", "|");

NoteEntries.push_back(newEntry);

}

currentPos = entryEnd + 1;

if (entryEnd == noteString.length()) break;

}

}

M5Cardputer.Display.clear();

SelectedMenuIndex = 0;

visibleOffset = 0;

currentState = STATE_TOP_MENU;

drawTopMenu();

lastFnCtrlTime = millis();

resetMenuTimer();

return;

} else {

drawPromptScreen("Try Again", "", "");

delay(1000);

resetMenuTimer();

}

}

}

void runTopMenu() {

if (checkForUniversalExit()) return;

if (!isSDInitialized) return;

std::vector<String> labels;

for (const auto& entry : TopMenuItems) {

labels.push_back(entry.label);

}

handleMenuNavigation(labels, SelectedMenuIndex, drawTopMenu);

}

void runColorMenu() {

if (checkForUniversalExit()) return;

if (!isSDInitialized) return;

std::vector<String> labels;

for (const auto& entry : ColorMenuItems) {

labels.push_back(entry.name);

}

handleMenuNavigation(labels, SelectedMenuIndex, drawColorMenu);

}

void runPassMenu() {

if (checkForUniversalExit()) return;

if (!isSDInitialized) return;

handleMenuNavigation(PassMenuDisplayItems, SelectedMenuIndex, drawPassMenu);

}

void runNoteMenu() {

if (checkForUniversalExit()) return;

if (!isSDInitialized) return;

handleMenuNavigation(NoteMenuDisplayItems, SelectedMenuIndex, drawNoteMenu);

}

void runPassEditMenu() {

if (checkForUniversalExit()) return;

if (!isSDInitialized) return;

PasswordEntry& entry = PassEntries[currentEditIndex];

if (M5Cardputer.Keyboard.isChange()) {

resetMenuTimer();

Keyboard_Class::KeysState status = M5Cardputer.Keyboard.keysState();

bool is_up_pressed = status.fn && (std::find(status.hid_keys.begin(), status.hid_keys.end(), KEY_SEMICOLON_HID) != status.hid_keys.end());

bool is_down_pressed = status.fn && (std::find(status.hid_keys.begin(), status.hid_keys.end(), KEY_PERIOD_HID) != status.hid_keys.end());

bool is_enter_pressed = status.enter;

if (is_up_pressed && PassDataIndex > 0) {

PassDataIndex--;

drawPassEditMenu();

delay(150);

} else if (is_down_pressed && PassDataIndex < 5) {

PassDataIndex++;

drawPassEditMenu();

delay(150);

}

else if (is_enter_pressed && status.fn) {

String data_to_send = "";

switch (PassDataIndex) {

case 1: data_to_send = entry.label; break;

case 2: data_to_send = entry.username; break;

case 3: data_to_send = entry.password; break;

}

if (data_to_send.length() > 0) {

sendEntryOverUSB(data_to_send);

}

drawPassEditMenu();

resetMenuTimer();

return;

}

else if (is_enter_pressed) {

String new_value = "";

bool saved = false;

switch (PassDataIndex) {

case 0:

buildPassMenuDisplayItems();

currentState = STATE_PASS_MENU;

drawPassMenu();

resetMenuTimer();

return;

case 1:

new_value = getEntryInput("NEW LABEL:");

if (currentState == STATE_KEYBOARD) return;

if (new_value.length() > 0) {

entry.label = new_value;

saved = saveData();

}

break;

case 2:

new_value = getEntryInput("NEW USERNAME:");

if (currentState == STATE_KEYBOARD) return;

if (new_value.length() > 0) {

entry.username = new_value;

saved = saveData();

}

break;

case 3:

new_value = getEntryInput("NEW PASSWORD");

if (currentState == STATE_KEYBOARD) return;

if (new_value.length() == 0) {

entry.password = generateStrongPassword();

saved = saveData();

} else if (new_value.length() > 0) {

entry.password = new_value;

saved = saveData();

}

break;

case 4:

entry.password = generateStrongPassword();

saved = saveData();

break;

case 5: {

PassEntries.erase(PassEntries.begin() + currentEditIndex);

saved = saveData();

if (saved) {

buildPassMenuDisplayItems();

SelectedMenuIndex = 1;

currentState = STATE_PASS_MENU;

drawPassMenu();

resetMenuTimer();

return;

} else {

drawPromptScreen("Could not delete", "", "");

delay(1000);

currentState = STATE_PASS_MENU;

drawPassMenu();

resetMenuTimer();

return;

}

}

}

if (PassDataIndex >= 1 && PassDataIndex <= 4 && !saved) {

drawPromptScreen("Save Failed!", "", "");

delay(1000);

}

drawPassEditMenu();

resetMenuTimer();

delay(150);

}

}

}

void runNoteEditMenu() {

if (checkForUniversalExit()) return;

if (!isSDInitialized) return;

if (currentEditIndex < 0 || currentEditIndex >= NoteEntries.size()) {

currentState = STATE_NOTE_MENU;

drawNoteMenu();

return;

}

NoteEntry& entry = NoteEntries[currentEditIndex];

if (M5Cardputer.Keyboard.isChange()) {

resetMenuTimer();

Keyboard_Class::KeysState status = M5Cardputer.Keyboard.keysState();

bool is_up_pressed = status.fn && (std::find(status.hid_keys.begin(), status.hid_keys.end(), KEY_SEMICOLON_HID) != status.hid_keys.end());

bool is_down_pressed = status.fn && (std::find(status.hid_keys.begin(), status.hid_keys.end(), KEY_PERIOD_HID) != status.hid_keys.end());

bool is_enter_pressed = status.enter;

if (is_up_pressed && PassDataIndex > 0) {

PassDataIndex--;

drawNoteEditMenu();

delay(150);

} else if (is_down_pressed && PassDataIndex < 3) {

PassDataIndex++;

drawNoteEditMenu();

delay(150);

}

else if (is_enter_pressed) {

String new_value = "";

bool saved = false;

switch (PassDataIndex) {

case 0:

buildNoteMenuDisplayItems();

currentState = STATE_NOTE_MENU;

drawNoteMenu();

resetMenuTimer();

return;

case 1:

new_value = getEntryInput("NEW TITLE:");

if (currentState == STATE_KEYBOARD) return;

if (new_value.length() > 0) {

entry.label = new_value;

saved = saveData();

}

break;

case 2:

cursorPos = entry.body.length();

bodyScrollOffset = 0;

currentState = STATE_NOTE_BODY_EDIT;

repeatingKey = 0;

return;

case 3: {

NoteEntries.erase(NoteEntries.begin() + currentEditIndex);

saved = saveData();

if (saved) {

buildNoteMenuDisplayItems();

SelectedMenuIndex = 1;

currentState = STATE_NOTE_MENU;

drawNoteMenu();

resetMenuTimer();

return;

} else {

drawPromptScreen("Could not delete", "", "");

delay(1000);

currentState = STATE_NOTE_MENU;

drawNoteMenu();

resetMenuTimer();

return;

}

}

}

if (PassDataIndex >= 1 && PassDataIndex <= 1 && !saved) {

drawPromptScreen("Save Failed!", "", "");

delay(1000);

}

drawNoteEditMenu();

resetMenuTimer();

delay(150);

}

}

}

void runNoteBodyEditScreen() {

if (checkForUniversalExit()) return;

if (currentEditIndex < 0 || currentEditIndex >= NoteEntries.size()) {

currentState = STATE_NOTE_EDIT;

drawNoteEditMenu();

return;

}

NoteEntry& entry = NoteEntries[currentEditIndex];

String& input = entry.body;

static String initialInput = "";

unsigned long currentMillis = millis();

if (currentMillis - lastActivityTime >= MENU_TIMEOUT_MS) {

timeoutToKeyboard();

return;

}

Keyboard_Class::KeysState status = M5Cardputer.Keyboard.keysState();

bool keySetChanged = M5Cardputer.Keyboard.isChange();

bool isFn = status.fn;

uint8_t currentActionKey = 0;

bool shouldProcess = false;

if (currentState == STATE_NOTE_BODY_EDIT && initialInput.length() == 0) {

initialInput = input;

}

if (status.enter && isFn) {

if (!saveData()) {

drawPromptScreen("Save Failed!", "", "");

delay(1000);

}

initialInput = "";

currentState = STATE_NOTE_EDIT;

drawNoteEditMenu();

resetMenuTimer();

return;

}

if (isFn && (std::find(status.hid_keys.begin(), status.hid_keys.end(), KEY_BACKTICK_HID) != status.hid_keys.end())) {

if (initialInput != input) {

input = initialInput;

}

initialInput = "";

currentState = STATE_NOTE_EDIT;

drawNoteEditMenu();

resetMenuTimer();

return;

}

if (keySetChanged) {

resetMenuTimer();

if (M5Cardputer.Keyboard.isPressed()) {

if (isFn) {

if (std::find(status.hid_keys.begin(), status.hid_keys.end(), KEY_BACKSPACE_HID) != status.hid_keys.end()) currentActionKey = KEY_DELETE;

else if (std::find(status.hid_keys.begin(), status.hid_keys.end(), KEY_COMMA_HID) != status.hid_keys.end()) currentActionKey = KEY_LEFT_ARROW;

else if (std::find(status.hid_keys.begin(), status.hid_keys.end(), KEY_SLASH_HID) != status.hid_keys.end()) currentActionKey = KEY_RIGHT_ARROW;

else if (std::find(status.hid_keys.begin(), status.hid_keys.end(), KEY_SEMICOLON_HID) != status.hid_keys.end()) currentActionKey = KEY_UP_ARROW;

else if (std::find(status.hid_keys.begin(), status.hid_keys.end(), KEY_PERIOD_HID) != status.hid_keys.end()) currentActionKey = KEY_DOWN_ARROW;

}

else if (status.del) {

currentActionKey = KEY_BACKSPACE_HID;

}

else if (status.enter) {

currentActionKey = KEY_ENTER_HID;

}

else if (status.word.size() > 0) {

currentActionKey = 0x01;

}

uint8_t newRepeatingKey = 0;

if (currentActionKey == KEY_DELETE || currentActionKey == KEY_BACKSPACE_HID ||

currentActionKey == KEY_LEFT_ARROW || currentActionKey == KEY_RIGHT_ARROW ||

currentActionKey == KEY_UP_ARROW || currentActionKey == KEY_DOWN_ARROW) {

newRepeatingKey = currentActionKey;

} else if (currentActionKey == 0x01) {

if (status.word.size() > 0) newRepeatingKey = status.word[0];

}

if (newRepeatingKey != repeatingKey) {

repeatingKey = newRepeatingKey;

if (repeatingKey != 0) {

lastKeyPressTime = currentMillis;

lastKeyRepeatTime = currentMillis;

}

}

shouldProcess = true;

} else {

repeatingKey = 0;

lastKeyPressTime = 0;

}

}

if (!keySetChanged && repeatingKey != 0) {

if (currentMillis - lastKeyPressTime >= KEY_REPEAT_DELAY_MS) {

if (currentMillis - lastKeyRepeatTime >= KEY_REPEAT_RATE_MS) {

currentActionKey = repeatingKey;

lastKeyRepeatTime = currentMillis;

shouldProcess = true;

}

}

}

if (shouldProcess && currentActionKey != 0) {

if (currentActionKey == KEY_BACKSPACE_HID && cursorPos > 0) {

input.remove(cursorPos - 1, 1);

cursorPos--;

} else if (currentActionKey == KEY_DELETE && cursorPos < input.length()) {

input.remove(cursorPos, 1);

} else if (currentActionKey == KEY_LEFT_ARROW) {

cursorPos = max(0, cursorPos - 1);

} else if (currentActionKey == KEY_RIGHT_ARROW) {

cursorPos = min((int)input.length(), cursorPos + 1);

} else if (currentActionKey == KEY_ENTER_HID) {

String temp_str = input.substring(0, cursorPos);

temp_str += "\n";

temp_str += input.substring(cursorPos);

input = temp_str;

cursorPos++;

}

else if (currentActionKey == KEY_UP_ARROW || currentActionKey == KEY_DOWN_ARROW) {

int lineStart = 0;

int lineIndex = 0;

int xOffset = 0;

int tempPos = 0;

while(tempPos <= cursorPos) {

int nextNewLine = input.indexOf('\n', tempPos);

if (nextNewLine == -1 || nextNewLine >= cursorPos) {

lineStart = tempPos;

xOffset = cursorPos - lineStart;

break;

}

tempPos = nextNewLine + 1;

lineIndex++;

}

int targetLineIndex = lineIndex + (currentActionKey == KEY_DOWN_ARROW ? 1 : -1);

if (targetLineIndex >= 0) {

int nextStart = 0;

int nextEnd = 0;

int currentTargetLine = 0;

bool lineFound = false;

tempPos = 0;

while(tempPos <= input.length()) {

int nextNewLine = input.indexOf('\n', tempPos);

if (currentTargetLine == targetLineIndex) {

nextStart = tempPos;

nextEnd = (nextNewLine == -1) ? input.length() : nextNewLine;

lineFound = true;

break;

}

if (nextNewLine == -1) break;

tempPos = nextNewLine + 1;

currentTargetLine++;

}

if (lineFound) {

int newPos = nextStart + min(xOffset, nextEnd - nextStart);

cursorPos = newPos;

}

else if (currentActionKey == KEY_DOWN_ARROW && targetLineIndex == currentTargetLine) {

cursorPos = input.length();

}

}

}

else if (currentActionKey == 0x01 || (currentActionKey != 0 && currentActionKey >= 32)) {

String chars_to_insert = "";

if (currentActionKey == 0x01) {

for (auto c : status.word) {

if (c != 0) {

chars_to_insert += (char)c;

}

}

} else {

if (currentActionKey >= 32) {

chars_to_insert += (char)currentActionKey;

}

}

if (chars_to_insert.length() > 0) {

String temp_str = input.substring(0, cursorPos);

temp_str += chars_to_insert;

temp_str += input.substring(cursorPos);

input = temp_str;

cursorPos += chars_to_insert.length();

}

}

cursorPos = min((int)input.length(), max(0, cursorPos));

delay(50);

}

drawNoteBodyEditScreen(input, cursorPos, bodyScrollOffset);

}

void runChangeMaster() {

if (checkForUniversalExit()) return;

if (!isSDInitialized) {

currentState = STATE_TOP_MENU;

drawTopMenu();

resetMenuTimer();

return;

}

String newPass1 = getPasswordInput("NEW PASSWORD");

if (currentState == STATE_KEYBOARD) return;

if (newPass1.length() == 0) {

currentState = STATE_TOP_MENU;

drawTopMenu();

resetMenuTimer();

return;

}

String newPass2 = getPasswordInput("CONFIRM NEW");

if (currentState == STATE_KEYBOARD) return;

resetMenuTimer();

if (newPass1 == newPass2) {

String oldPass = MASTER_PASSWORD;

MASTER_PASSWORD = newPass1;

generateRandomSalt(CURRENT_SALT);

if (!saveData()) {

MASTER_PASSWORD = oldPass;

drawPromptScreen("SAVE FAILED", "", "");

delay(1000);

resetMenuTimer();

} else {

drawPromptScreen("Password Changed", "", "");

delay(1000);

resetMenuTimer();

}

} else {

drawPromptScreen("didn't match", "", "");

delay(1000);

resetMenuTimer();

}

currentState = STATE_TOP_MENU;

drawTopMenu();

}

bool saveConfigData() {

if (!isSDInitialized) return false;

File dataFile = SD.open(SD_CONFIG_FILE_PATH, FILE_WRITE);

if (dataFile) {

char hex_color[5];

sprintf(hex_color, "%04X", MENU_HIGHLIGHT_COLOR);

dataFile.print(hex_color);

dataFile.close();

return true;

}

return false;

}

void loadConfigData() {

if (!isSDInitialized) return;

File dataFile = SD.open(SD_CONFIG_FILE_PATH);

if (!dataFile || dataFile.isDirectory()) {

MENU_HIGHLIGHT_COLOR = RED;

saveConfigData();

return;

}

String configString = "";

while (dataFile.available()) {

configString += (char)dataFile.read();

}

dataFile.close();

if (configString.length() == 4) {

unsigned long color565 = strtoul(configString.c_str(), NULL, 16);

if (color565 != 0) {

MENU_HIGHLIGHT_COLOR = (uint16_t)color565;

}

}

}

void generateRandomSalt(uint8_t* salt_out) {

esp_fill_random(salt_out, AES_BLOCK_SIZE);

}

void deriveKey(const String& masterPass, const uint8_t* salt, uint8_t* key_out) {

if (masterPass.length() == 0) {

memset(key_out, 0, AES_KEY_SIZE);

return;

}

const uint8_t* password = (const uint8_t*)masterPass.c_str();

size_t passwordLen = masterPass.length();

int ret = mbedtls_pkcs5_pbkdf2_hmac_ext(

MBEDTLS_MD_SHA256,

password,

passwordLen,

salt,

AES_BLOCK_SIZE,

PBKDF2_ITERATIONS,

AES_KEY_SIZE,

key_out

);

if (ret != 0) {

memset(key_out, 0, AES_KEY_SIZE);

Serial.println("PBKDF2 Error");

}

}

void initializeVaultFile() {

if (SD.exists(SD_VAULT_FILE_PATH)) {

return;

}

uint8_t new_salt[AES_BLOCK_SIZE];

generateRandomSalt(new_salt);

memcpy(CURRENT_SALT, new_salt, AES_BLOCK_SIZE);

String temp_master = MASTER_PASSWORD;

String rawData = temp_master + "@@@" + "" + "@@@" + "";

String encryptedData = encryptAES(rawData, temp_master, CURRENT_SALT);

File dataFile = SD.open(SD_VAULT_FILE_PATH, FILE_WRITE);

if (dataFile) {

dataFile.print(encryptedData);

dataFile.close();

}

}

String encryptAES(const String& data, const String& masterPass, const uint8_t* salt) {

if (data.length() == 0) return "";

uint8_t key[AES_KEY_SIZE];

deriveKey(masterPass, salt, key);

size_t dataLen = data.length();

size_t paddedLen = dataLen + (AES_BLOCK_SIZE - (dataLen % AES_BLOCK_SIZE));

uint8_t buffer[paddedLen];

uint8_t cipherText[paddedLen];

memcpy(buffer, data.c_str(), dataLen);

uint8_t pad_val = paddedLen - dataLen;

memset(buffer + dataLen, pad_val, pad_val);

uint8_t local_IV[AES_BLOCK_SIZE];

memcpy(local_IV, IV, AES_BLOCK_SIZE);

aes_cbc.setKey(key, AES_KEY_SIZE);

aes_cbc.setIV(local_IV, AES_BLOCK_SIZE);

aes_cbc.encrypt(cipherText, buffer, paddedLen);

uint8_t hmac_tag[HMAC_TAG_SIZE];

sha256_hmac.resetHMAC(key, AES_KEY_SIZE);

sha256_hmac.update(cipherText, paddedLen);

sha256_hmac.finalizeHMAC(key, AES_KEY_SIZE, hmac_tag, HMAC_TAG_SIZE);

String outputHex = "";

for (size_t i = 0; i < AES_BLOCK_SIZE; i++) {

char hex[3];

sprintf(hex, "%02X", salt[i]);

outputHex += hex;

}

outputHex += ":";

for (size_t i = 0; i < paddedLen; i++) {

char hex[3];

sprintf(hex, "%02X", cipherText[i]);

outputHex += hex;

}

for (size_t i = 0; i < HMAC_TAG_SIZE; i++) {

char hex[3];

sprintf(hex, "%02X", hmac_tag[i]);

outputHex += hex;

}

return String(dataLen) + ":" + outputHex;

}

String decryptAES(const String& encryptedData, const String& masterPass) {

if (encryptedData.length() == 0) return "";

int lenSeparatorPos = encryptedData.indexOf(':');

if (lenSeparatorPos == -1) return "";

size_t actualDataLen = encryptedData.substring(0, lenSeparatorPos).toInt();

String hexString = encryptedData.substring(lenSeparatorPos + 1);

int saltSeparatorPos = hexString.indexOf(':');

if (saltSeparatorPos == -1) return "";

String saltHex = hexString.substring(0, saltSeparatorPos);

String cipherHmacHex = hexString.substring(saltSeparatorPos + 1);

if (saltHex.length() != AES_BLOCK_SIZE * 2 || cipherHmacHex.length() % 2 != 0) return "";

uint8_t salt[AES_BLOCK_SIZE];

for (size_t i = 0; i < AES_BLOCK_SIZE; i++) {

String byteStr = saltHex.substring(i * 2, i * 2 + 2);

salt[i] = (uint8_t)strtol(byteStr.c_str(), NULL, 16);

}

memcpy(CURRENT_SALT, salt, AES_BLOCK_SIZE);

size_t totalHexLen = cipherHmacHex.length() / 2;

size_t hmac_size = HMAC_TAG_SIZE;

if (totalHexLen < hmac_size || (totalHexLen - hmac_size) % AES_BLOCK_SIZE != 0) return "";

size_t cipherTextLen = totalHexLen - hmac_size;

uint8_t buffer[cipherTextLen];

uint8_t received_tag[hmac_size];

for (size_t i = 0; i < cipherTextLen; i++) {

String byteStr = cipherHmacHex.substring(i * 2, i * 2 + 2);

buffer[i] = (uint8_t)strtol(byteStr.c_str(), NULL, 16);

}

for (size_t i = 0; i < hmac_size; i++) {

String byteStr = cipherHmacHex.substring((cipherTextLen + i) * 2, (cipherTextLen + i) * 2 + 2);

received_tag[i] = (uint8_t)strtol(byteStr.c_str(), NULL, 16);

}

uint8_t key[AES_KEY_SIZE];

deriveKey(masterPass, salt, key);

uint8_t expected_tag[hmac_size];

sha256_hmac.resetHMAC(key, AES_KEY_SIZE);

sha256_hmac.update(buffer, cipherTextLen);

sha256_hmac.finalizeHMAC(key, AES_KEY_SIZE, expected_tag, hmac_size);

bool auth_success = true;

for(size_t i = 0; i < hmac_size; ++i) {

if (received_tag[i] != expected_tag[i]) {

auth_success = false;

break;

}

}

if (!auth_success) {

return "";

}

uint8_t local_IV[AES_BLOCK_SIZE];

memcpy(local_IV, IV, AES_BLOCK_SIZE);

aes_cbc.setKey(key, AES_KEY_SIZE);

aes_cbc.setIV(local_IV, AES_BLOCK_SIZE);

aes_cbc.decrypt(buffer, buffer, cipherTextLen);

size_t paddingLen = buffer[cipherTextLen - 1];

if (paddingLen < 1 || paddingLen > AES_BLOCK_SIZE || actualDataLen != (cipherTextLen - paddingLen)) {

return "";

}

for(size_t i = 1; i <= paddingLen; ++i) {

if(buffer[cipherTextLen - i] != paddingLen) {

return "";

}

}

buffer[actualDataLen] = '\0';

return String((char*)buffer);

}

bool saveData() {

if (!isSDInitialized) return false;

String rawData = MASTER_PASSWORD;

String passData = "";

for (size_t i = 0; i < PassEntries.size(); ++i) {

if (i > 0) passData += "|";

passData += PassEntries[i].label + "," + PassEntries[i].username + "," + PassEntries[i].password;

}

String noteData = "";

for (size_t i = 0; i < NoteEntries.size(); ++i) {

if (i > 0) noteData += "|";

String safeBody = NoteEntries[i].body;

safeBody.replace("|", "###");

noteData += NoteEntries[i].label + "," + safeBody;

}

rawData += "@@@" + passData;

rawData += "@@@" + noteData;

String encryptedData = encryptAES(rawData, MASTER_PASSWORD, CURRENT_SALT);

File dataFile = SD.open(SD_VAULT_FILE_PATH, FILE_WRITE);

if (dataFile) {

dataFile.print(encryptedData);

dataFile.close();

ENCRYPTED_VAULT_STRING = encryptedData;

return true;

}

return false;

}

bool loadEncryptedData() {

if (!isSDInitialized) {

ENCRYPTED_VAULT_STRING = "";

return false;

}

File dataFile = SD.open(SD_VAULT_FILE_PATH);

if (!dataFile || dataFile.isDirectory()) {

ENCRYPTED_VAULT_STRING = "";

return false;

}

ENCRYPTED_VAULT_STRING = "";

while (dataFile.available()) {

ENCRYPTED_VAULT_STRING += (char)dataFile.read();

}

dataFile.close();

return ENCRYPTED_VAULT_STRING.length() > 0;

}

String generateStrongPassword() {

const char* upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

const char* lower = "abcdefghijklmnopqrstuvwxyz";

const char* numbers = "0123456789";

const char* symbols = "!@#$%^&*()-_+={}|<>/?~";

String all_chars = String(upper) + String(lower) + String(lower) + String(numbers) + String(numbers) + String(symbols);

int len = all_chars.length();

String password = "";

const int PASSWORD_LENGTH = 16;

password += upper[rand() % strlen(upper)];

password += lower[rand() % strlen(lower)];

password += numbers[rand() % strlen(numbers)];

password += symbols[rand() % strlen(symbols)];

while (password.length() < PASSWORD_LENGTH) {

password += all_chars[rand() % len];

}

char password_arr[PASSWORD_LENGTH + 1];

password.toCharArray(password_arr, PASSWORD_LENGTH + 1);

for(int i = PASSWORD_LENGTH - 1; i > 0; i--) {

int j = rand() % (i + 1);

char temp = password_arr[i];

password_arr[i] = password_arr[j];

password_arr[j] = temp;

}

return String(password_arr);

}

String getPasswordInput(const char* prompt, const String& expected_password) {

String input = "";

const char* status_msg = "";

drawPromptScreen(prompt, "", status_msg);

while (true) {

M5Cardputer.update();

if (checkForUniversalExit()) return "";

if (millis() - lastActivityTime >= MENU_TIMEOUT_MS) {

timeoutToKeyboard();

return "";

}

if (M5Cardputer.Keyboard.isChange()) {

resetMenuTimer();

Keyboard_Class::KeysState status = M5Cardputer.Keyboard.keysState();

if (M5Cardputer.Keyboard.isPressed()) {

for (auto c : status.word) {

input += c;

}

if (status.del && input.length() > 0) {

input.remove(input.length() - 1);

}

if (status.enter) {

if (expected_password.length() > 0 && input != expected_password) {

input = "";

drawPromptScreen(prompt, "", "INCORRECT");

delay(500);

status_msg = "";

continue;

}

return input;

}

String masked_input = "";

for(int i=0; i < input.length(); i++) {

masked_input += '*';

}

drawPromptScreen(prompt, masked_input, status_msg);

delay(100);

}

}

}

}

String getEntryInput(const char* prompt) {

String input = "";

canvas.fillScreen(BLACK);

canvas.setTextFont(&fonts::FreeMonoBold12pt7b);

canvas.setTextSize(1.0);

canvas.setTextColor(MENU_HIGHLIGHT_COLOR, BLACK);

canvas.drawString(prompt, 10, 10);

canvas.pushSprite(0, 0);

while (true) {

M5Cardputer.update();

if (checkForUniversalExit()) return "";

if (millis() - lastActivityTime >= MENU_TIMEOUT_MS) {

timeoutToKeyboard();

return "";

}

if (M5Cardputer.Keyboard.isChange()) {

resetMenuTimer();

Keyboard_Class::KeysState status = M5Cardputer.Keyboard.keysState();

if (M5Cardputer.Keyboard.isPressed()) {

for (auto c : status.word) {

if (c != 0) {

input += c;

}

}

if (status.del && input.length() > 0) {

input.remove(input.length() - 1);

}

if (status.enter) {

canvas.fillScreen(BLACK);

canvas.pushSprite(0, 0);

return input;

}

canvas.fillRect(0, 30, canvas.width(), 20, BLACK);

canvas.setTextColor(WHITE, BLACK);

canvas.drawString(input, 10, 30);

canvas.pushSprite(0, 0);

delay(100);

}

}

}

}
