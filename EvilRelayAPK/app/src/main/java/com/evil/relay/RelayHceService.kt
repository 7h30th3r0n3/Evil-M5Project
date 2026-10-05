package com.evil.relay

import android.nfc.cardemulation.HostApduService
import android.os.Bundle

/*
 * HCE card emulation (EMULATOR mode, phone side). Android routes the terminal's
 * APDUs here (by AID, see res/xml/apduservice.xml). Each APDU is forwarded over
 * WiFi to the reader (phone or Cardputer) and the card response is returned.
 *
 * Limit: Android HCE sets its own random UID and does not expose ATS/SAK control,
 * so the emulated card identity is Android's, not the real card's. The APDU layer
 * (PPSE / SELECT AID / GPO / READ RECORD / GENERATE AC) is fully relayed.
 */
class RelayHceService : HostApduService() {

    override fun processCommandApdu(apdu: ByteArray?, extras: Bundle?): ByteArray {
        if (apdu == null) return SW_6F00
        Relay.log("HCE <- " + Relay.hex(apdu))
        val resp = Relay.relayApdu(apdu)
        if (resp == null || resp.isEmpty()) {
            Relay.log("HCE -> 6F00 (no reader / timeout)")
            return SW_6F00
        }
        Relay.log("HCE -> " + resp.size + "B")
        return resp
    }

    override fun onDeactivated(reason: Int) {
        Relay.log("HCE deactivated (" + reason + ")")
    }

    companion object {
        private val SW_6F00 = byteArrayOf(0x6F.toByte(), 0x00)
    }
}
