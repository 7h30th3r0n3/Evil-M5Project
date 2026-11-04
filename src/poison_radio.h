// ============================================================================
//  poison_radio.h — shared SX1262 layer for the LoRa PoCs (PoisonMesh / PoisonCore)
// ----------------------------------------------------------------------------
//  Cap LoRa-1262 on the Cardputer ADV. Same radio layer used by the two
//  standalone PoCs (PoisonMesh sync 0x2B / PoisonCore sync 0x12), ported into a
//  single wrapper so the SX1262 handling is not duplicated inside the firmware.
//
//  Created/destroyed around each menu entry: this way it does not clash with the
//  "totem" LoRa layer that uses the same pins (only one is used at a time).
// ============================================================================
#pragma once

#include <SPI.h>
#include <RadioLib.h>

// ---- LoRa SPI pins (Cap LoRa-1262) -----------------------------------------
#define POISON_LORA_SCK   40
#define POISON_LORA_MOSI  14
#define POISON_LORA_MISO  39
#define POISON_LORA_NSS   5
#define POISON_LORA_RST   3
#define POISON_LORA_IRQ   4
#define POISON_LORA_BUSY  6

static SX1262*   poison_sx     = nullptr;
static Module*   poison_sx_mod = nullptr;
static volatile bool poison_lora_irq_flag = false;
static bool      poison_lora_on  = false;
static bool      poison_lora_rx  = false;

static void IRAM_ATTR poison_lora_isr() {
    poison_lora_irq_flag = true;
}

// Fast probe of the LoRaSyncWord register to detect the physical presence of the
// SX1262 WITHOUT going through RadioLib begin(), which waits for reset/BUSY and
// can hang 5-10 s if no HAT is connected. A deterministic read == live chip.
static bool poison_lora_probe() {
    pinMode(POISON_LORA_NSS, OUTPUT);
    digitalWrite(POISON_LORA_NSS, HIGH);

    auto rd = [&]() -> uint16_t {
        SPI.beginTransaction(SPISettings(2000000, MSBFIRST, SPI_MODE0));
        digitalWrite(POISON_LORA_NSS, LOW);
        SPI.transfer(0x1D);          // ReadRegister
        SPI.transfer(0x07);          // 0x0740 >> 8  (LoRaSyncWord MSB)
        SPI.transfer(0x40);
        uint8_t m = SPI.transfer(0x00);
        uint8_t l = SPI.transfer(0x00);
        digitalWrite(POISON_LORA_NSS, HIGH);
        SPI.endTransaction();
        return ((uint16_t)m << 8) | l;
    };

    uint16_t a = rd(), b = rd(), c = rd();
    return (a == b && b == c && a != 0x0000 && a != 0xFFFF);
}

static void poisonRadioEnd();

static bool poisonRadioBegin(float freqMHz, float bwKHz, uint8_t sf, uint8_t cr,
                             uint16_t syncWord, int8_t txPower, uint16_t preamble,
                             float tcxo, uint8_t crcMode) {
    poisonRadioEnd();

    SPI.begin(POISON_LORA_SCK, POISON_LORA_MISO, POISON_LORA_MOSI, POISON_LORA_NSS);
    if (!poison_lora_probe()) {
        return false;
    }

    poison_sx_mod = new(std::nothrow) Module(POISON_LORA_NSS, POISON_LORA_IRQ,
                                             POISON_LORA_RST, POISON_LORA_BUSY);
    if (!poison_sx_mod) return false;
    poison_sx = new(std::nothrow) SX1262(poison_sx_mod);
    if (!poison_sx) {
        delete poison_sx_mod;
        poison_sx_mod = nullptr;
        return false;
    }

    if (txPower > 22) txPower = 22;
    if (txPower < -9) txPower = -9;

    int st = poison_sx->begin(freqMHz, bwKHz, sf, cr, syncWord, txPower,
                              preamble, tcxo, false);
    if (st != RADIOLIB_ERR_NONE) {
        delete poison_sx;     poison_sx = nullptr;
        delete poison_sx_mod; poison_sx_mod = nullptr;
        return false;
    }

    poison_sx->setDio2AsRfSwitch(true);
    poison_sx->setPreambleLength(preamble);
    poison_sx->setCurrentLimit(140.0f);
    poison_sx->setCRC(crcMode);
    poison_sx->setDio1Action(poison_lora_isr);

    poison_lora_on = true;
    poison_lora_irq_flag = false;
    return true;
}

static void poisonRadioEnd() {
    if (poison_sx) {
        poison_sx->standby();
        detachInterrupt(digitalPinToInterrupt(POISON_LORA_IRQ));
        delete poison_sx; poison_sx = nullptr;
    }
    if (poison_sx_mod) { delete poison_sx_mod; poison_sx_mod = nullptr; }
    poison_lora_on = false;
    poison_lora_rx = false;
    poison_lora_irq_flag = false;
}

static bool poisonRadioStartRx() {
    if (!poison_lora_on || !poison_sx) return false;
    poison_lora_irq_flag = false;
    if (poison_sx->startReceive() != RADIOLIB_ERR_NONE) return false;
    poison_lora_rx = true;
    return true;
}

static bool poisonRadioAvailable() {
    return poison_lora_on && poison_lora_irq_flag;
}

static int poisonRadioTx(const uint8_t* data, size_t len) {
    if (!poison_lora_on || !poison_sx || len == 0) return -100;
    bool wasRx = poison_lora_rx;
    int st = poison_sx->transmit(const_cast<uint8_t*>(data), len);
    if (wasRx) poisonRadioStartRx();
    else poison_lora_rx = false;
    return (st == RADIOLIB_ERR_NONE) ? 0 : st;
}

// Read the pending packet. Returns length (>0), or <=0 if none / error.
static int poisonRadioRead(uint8_t* buf, size_t maxLen, int* rssi) {
    if (!poison_lora_on || !poison_sx || !poison_lora_irq_flag) return -1;
    poison_lora_irq_flag = false;
    size_t n = poison_sx->getPacketLength();
    if (n == 0 || n > maxLen) { poison_sx->startReceive(); return -1; }
    int st = poison_sx->readData(buf, n);
    if (rssi) *rssi = (int)poison_sx->getRSSI();
    poison_sx->startReceive();
    if (st == RADIOLIB_ERR_NONE || st == RADIOLIB_ERR_CRC_MISMATCH) return (int)n;
    return -1;
}
