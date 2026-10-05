#pragma once
// awok_audio_stub.h — no-op stand-ins for ESP8266Audio (guarded out on AWOK:
// no speaker/codec on the display port). Lets AudioOutputM5Speaker + play()/stop()
// COMPILE as no-ops. Included by awok_m5_shim.h under AWOK_MINI.
#include <Arduino.h>
static const unsigned int hertz = 44100;   // used by AudioOutputM5Speaker::flush()

class AudioOutput {
 public:
  virtual ~AudioOutput() {}
  virtual bool begin() { return false; }
  virtual bool ConsumeSample(int16_t[2]) { return false; }
  virtual bool stop() { return false; }
  virtual void flush() {}
  virtual bool SetRate(int) { return true; }
  virtual bool SetBitsPerSample(int) { return true; }
  virtual bool SetChannels(int) { return true; }
  virtual bool SetGain(float) { return true; }
};
class AudioFileSource { public: virtual ~AudioFileSource() {} };
class AudioFileSourceSD {
 public:
  AudioFileSourceSD() {}
  bool open(const char*) { return false; }
  bool close() { return true; }
};
class AudioFileSourceID3 {
 public:
  AudioFileSourceID3(void*) {}
  bool open(const char*) { return false; }
  bool close() { return true; }
  void RegisterMetadataCB(void*, void*) {}
};
class AudioGeneratorMP3 {
 public:
  bool begin(void*, void*) { return false; }
  bool isRunning() { return false; }
  bool loop() { return false; }
  bool stop() { return true; }
};
