package com.evil.relay

import java.io.InputStream
import java.io.OutputStream
import java.net.Socket

/*
 * Shared relay core: TCP framing and the HCE <-> reader bridge.
 *
 * Frame = MAGIC(0x5A) type seq lenHi lenLo payload
 *   type 1 IDENT (reader -> emulator) : uidLen uid.. atqa0 atqa1 sak atsLen ats..
 *   type 2 REQ   (emulator -> reader) : APDU from the terminal
 *   type 3 RESP  (reader -> emulator) : card response
 *
 * In EMULATOR mode this app is the TCP SERVER; the reader (a phone or a Cardputer)
 * is the CLIENT. The reader sends IDENT once, then the terminal taps the emulator,
 * Android routes the APDUs to RelayHceService, which calls relayApdu() to forward
 * each APDU to the reader and return the card response to the terminal.
 */
object Relay {
    const val MAGIC = 0x5A.toByte()

    // Socket to the reader (set by the emulator TCP server once a reader connects).
    @Volatile var readerSocket: Socket? = null
    // UI log sink (set by MainActivity).
    @Volatile var logSink: ((String) -> Unit)? = null
    @Volatile var apduCount: Int = 0

    fun log(s: String) { logSink?.invoke(s) }

    class Frame(val type: Byte, val seq: Byte, val payload: ByteArray)

    fun sendFrame(out: OutputStream, type: Int, seq: Int, payload: ByteArray) {
        val len = payload.size
        val hdr = byteArrayOf(
            MAGIC, type.toByte(), seq.toByte(),
            ((len shr 8) and 0xFF).toByte(), (len and 0xFF).toByte()
        )
        synchronized(out) {
            out.write(hdr)
            if (len > 0) out.write(payload)
            out.flush()
        }
    }

    fun readFrame(inp: InputStream): Frame? {
        val hdr = readN(inp, 5) ?: return null
        if (hdr[0] != MAGIC) return null
        val len = ((hdr[3].toInt() and 0xFF) shl 8) or (hdr[4].toInt() and 0xFF)
        val payload = if (len > 0) (readN(inp, len) ?: return null) else ByteArray(0)
        return Frame(hdr[1], hdr[2], payload)
    }

    private fun readN(inp: InputStream, n: Int): ByteArray? {
        val b = ByteArray(n); var r = 0
        while (r < n) {
            val k = try { inp.read(b, r, n - r) } catch (e: Exception) { return null }
            if (k < 0) return null
            r += k
        }
        return b
    }

    // Called from the HCE service: forward one terminal APDU to the reader, return card response.
    @Synchronized
    fun relayApdu(apdu: ByteArray): ByteArray? {
        val s = readerSocket ?: return null
        return try {
            val out = s.getOutputStream()
            val inp = s.getInputStream()
            sendFrame(out, 2, 0, apdu)                 // REQ
            val f = readFrame(inp) ?: return null       // RESP
            if (f.type.toInt() and 0xFF == 3) {
                apduCount++
                f.payload
            } else null
        } catch (e: Exception) {
            null
        }
    }

    fun hex(b: ByteArray): String = b.joinToString("") { "%02X".format(it.toInt() and 0xFF) }
}
