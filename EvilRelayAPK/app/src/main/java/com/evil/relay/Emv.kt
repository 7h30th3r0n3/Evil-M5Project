package com.evil.relay

import android.nfc.tech.IsoDep

/*
 * Standalone EMV contactless reader (read-only, no network).
 *
 * Runs the usual EMV flow against the card: SELECT PPSE -> SELECT AID -> GET
 * PROCESSING OPTIONS -> READ RECORD over the AFL, then parses the BER-TLV to pull
 * the data a contactless card exposes WITHOUT any authentication: PAN, expiry,
 * cardholder name (when present), Track 2 equivalent, AID / application label,
 * country, currency. No PIN, no CVV2 (not on the chip), no reusable secret.
 *
 * This is the same information the Flipper / Evil "EMV reader" shows. For use on
 * your own cards only.
 */
object Emv {

    data class Info(
        var scheme: String = "",
        var aid: String = "",
        var appLabel: String = "",
        var pan: String = "",
        var expiry: String = "",
        var effective: String = "",
        var cardholder: String = "",
        var track2: String = "",
        var currency: String = "",
        var country: String = "",
        var panSeq: String = "",
        var ok: Boolean = false,
        val raw: StringBuilder = StringBuilder()
    )

    // ---------- hex helpers ----------
    fun hex(b: ByteArray, off: Int = 0, len: Int = b.size): String {
        val sb = StringBuilder()
        for (i in off until off + len) sb.append("%02X".format(b[i].toInt() and 0xFF))
        return sb.toString()
    }
    private fun fromHex(s: String): ByteArray {
        val t = s.replace(" ", "")
        val out = ByteArray(t.length / 2)
        for (i in out.indices) out[i] = ((Character.digit(t[2 * i], 16) shl 4) + Character.digit(t[2 * i + 1], 16)).toByte()
        return out
    }
    private fun sw9000(r: ByteArray) =
        r.size >= 2 && (r[r.size - 2].toInt() and 0xFF) == 0x90 && (r[r.size - 1].toInt() and 0xFF) == 0x00

    // ---------- BER-TLV ----------
    // Find the first occurrence of a (possibly multi-byte) tag, recursing into constructed objects.
    fun findTag(buf: ByteArray, tag: Int): ByteArray? {
        var i = 0
        while (i < buf.size) {
            var t = buf[i].toInt() and 0xFF; i++
            val constructed = (t and 0x20) != 0
            if ((t and 0x1F) == 0x1F) {
                while (i < buf.size) { val b = buf[i].toInt() and 0xFF; t = (t shl 8) or b; i++; if (b and 0x80 == 0) break }
            }
            if (i >= buf.size) break
            var len = buf[i].toInt() and 0xFF; i++
            if (len and 0x80 != 0) {
                val n = len and 0x7F; len = 0
                for (k in 0 until n) { if (i >= buf.size) return null; len = (len shl 8) or (buf[i].toInt() and 0xFF); i++ }
            }
            if (i + len > buf.size) break
            val value = buf.copyOfRange(i, i + len)
            if (t == tag) return value
            if (constructed) { val r = findTag(value, tag); if (r != null) return r }
            i += len
        }
        return null
    }

    // Collect all AID values (tag 4F) from a PPSE / directory response.
    fun findAllAids(buf: ByteArray): List<ByteArray> {
        val res = ArrayList<ByteArray>()
        fun walk(b: ByteArray) {
            var i = 0
            while (i < b.size) {
                var t = b[i].toInt() and 0xFF; i++
                val constructed = (t and 0x20) != 0
                if ((t and 0x1F) == 0x1F) { while (i < b.size) { val x = b[i].toInt() and 0xFF; t = (t shl 8) or x; i++; if (x and 0x80 == 0) break } }
                if (i >= b.size) break
                var len = b[i].toInt() and 0xFF; i++
                if (len and 0x80 != 0) { val n = len and 0x7F; len = 0; for (k in 0 until n) { if (i >= b.size) return; len = (len shl 8) or (b[i].toInt() and 0xFF); i++ } }
                if (i + len > b.size) break
                val v = b.copyOfRange(i, i + len)
                when {
                    t == 0x4F -> res.add(v)
                    constructed -> walk(v)
                }
                i += len
            }
        }
        walk(buf)
        return res
    }

    // ---------- field decoders ----------
    private fun panFromBcd(b: ByteArray): String {
        val sb = StringBuilder()
        for (by in b) {
            val hi = (by.toInt() and 0xF0) shr 4; val lo = by.toInt() and 0x0F
            if (hi == 0xF) break; sb.append(hi)
            if (lo == 0xF) break; sb.append(lo)
        }
        return sb.toString()
    }
    private fun panFromTrack2(b: ByteArray): String {
        val sb = StringBuilder()
        loop@ for (by in b) {
            for (nib in intArrayOf((by.toInt() and 0xF0) shr 4, by.toInt() and 0x0F)) {
                if (nib == 0x0D || nib == 0x0F) break@loop   // 'D' separator / padding
                sb.append(nib)
            }
        }
        return sb.toString()
    }
    private fun track2After(b: ByteArray): String {
        // nibble stream after the 'D' separator = YYMM SС ...
        val nibs = StringBuilder()
        for (by in b) { nibs.append("%02X".format(by.toInt() and 0xFF)) }
        val d = nibs.indexOf("D").let { if (it < 0) nibs.indexOf("d") else it }
        return if (d in 0 until nibs.length - 4) nibs.substring(d + 1) else ""
    }
    private fun expiryYYMMDD(b: ByteArray): String {
        if (b.size < 2) return ""
        val yy = "%02X".format(b[0].toInt() and 0xFF)
        val mm = "%02X".format(b[1].toInt() and 0xFF)
        return "$mm/$yy"
    }
    private fun expiryFromTrack2(b: ByteArray): String {
        val a = track2After(b)
        return if (a.length >= 4) "${a.substring(2, 4)}/${a.substring(0, 2)}" else ""
    }

    fun scheme(aidHex: String): String {
        val a = aidHex.uppercase()
        return when {
            a.startsWith("A0000000031") || a.startsWith("A0000000032") -> "Visa"
            a.startsWith("A0000000041") || a.startsWith("A0000000043") -> "Mastercard"
            a.startsWith("A0000000421") || a.startsWith("A0000000422") -> "CB"
            a.startsWith("A00000002501") || a.startsWith("A000000025") -> "Amex"
            a.startsWith("A0000000651") -> "JCB"
            a.startsWith("A0000001523") || a.startsWith("A0000001524") -> "Discover"
            a.startsWith("A000000333") -> "UnionPay"
            else -> "EMV"
        }
    }
    private fun u16(b: ByteArray) = if (b.size >= 2) ((b[0].toInt() and 0xFF) shl 8) or (b[1].toInt() and 0xFF) else 0
    private fun country(b: ByteArray): String = when (u16(b)) {
        0x0250 -> "France"; 0x0276 -> "Germany"; 0x0826 -> "UK"; 0x0840 -> "USA"
        0x0724 -> "Spain"; 0x0380 -> "Italy"; 0x0056 -> "Belgium"; 0x0528 -> "Netherlands"
        0x0756 -> "Switzerland"; 0x0978 -> "EU"; else -> "%04X".format(u16(b))
    }
    private fun currency(b: ByteArray): String = when (u16(b)) {
        0x0978 -> "EUR"; 0x0826 -> "GBP"; 0x0840 -> "USD"; 0x0756 -> "CHF"
        0x0392 -> "JPY"; 0x0124 -> "CAD"; 0x0036 -> "AUD"; else -> "%04X".format(u16(b))
    }

    // ---------- GPO / PDOL ----------
    // Build the GPO command data (83 <len> <pdol-values>); fills each PDOL tag with a plausible
    // default so the card returns the AFL. No PDOL -> "83 00".
    private fun buildGpoData(pdol: ByteArray?): ByteArray {
        if (pdol == null || pdol.isEmpty()) return byteArrayOf(0x83.toByte(), 0x00)
        val vals = ArrayList<Byte>()
        var i = 0
        while (i < pdol.size) {
            var t = pdol[i].toInt() and 0xFF; i++
            if ((t and 0x1F) == 0x1F) { while (i < pdol.size) { val x = pdol[i].toInt() and 0xFF; t = (t shl 8) or x; i++; if (x and 0x80 == 0) break } }
            if (i >= pdol.size) break
            val len = pdol[i].toInt() and 0xFF; i++
            val d = defaultFor(t, len)
            for (bb in d) vals.add(bb)
        }
        val out = ArrayList<Byte>()
        out.add(0x83.toByte()); out.add(vals.size.toByte()); out.addAll(vals)
        return out.toByteArray()
    }
    private fun defaultFor(tag: Int, len: Int): ByteArray {
        val b = ByteArray(len)
        val preset: ByteArray? = when (tag) {
            0x9F66 -> fromHex("36000000")          // TTQ (Visa: online, contactless)
            0x9F02 -> fromHex("000000000100")      // amount = 1.00
            0x9F1A -> fromHex("0250")              // terminal country = FR
            0x5F2A -> fromHex("0978")              // tx currency = EUR
            0x9A   -> fromHex("250101")            // date YYMMDD
            0x9C   -> fromHex("00")                // tx type = purchase
            0x9F37 -> fromHex("12345678")          // unpredictable number
            0x9F35 -> fromHex("22")                // terminal type
            0x9F40 -> fromHex("F000F0A001")        // additional terminal caps
            else   -> null
        }
        if (preset != null) for (k in 0 until len) b[k] = if (k < preset.size) preset[k] else 0
        return b
    }

    // ---------- main read ----------
    fun readCard(iso: IsoDep): Info {
        val info = Info()
        iso.timeout = 3000
        var r = iso.transceive(fromHex("00A404000E325041592E5359532E444446303100"))  // SELECT PPSE
        info.raw.append("PPSE -> ${hex(r)}\n")
        var aids = if (sw9000(r)) findAllAids(r.copyOfRange(0, r.size - 2)) else emptyList()
        if (aids.isEmpty()) aids = listOf(
            fromHex("A0000000031010"), fromHex("A0000000041010"),
            fromHex("A0000000421010"), fromHex("A00000002501")
        )
        for (aid in aids) {
            val sel = fromHex("00A40400") + byteArrayOf(aid.size.toByte()) + aid + byteArrayOf(0)
            r = iso.transceive(sel)
            info.raw.append("SELECT ${hex(aid)} -> ${hex(r)}\n")
            if (!sw9000(r)) continue
            val fci = r.copyOfRange(0, r.size - 2)
            info.aid = hex(aid); info.scheme = scheme(info.aid)
            findTag(fci, 0x50)?.let { val s = String(it).trim(); if (s.isNotEmpty()) info.appLabel = s }
            val gpo = fromHex("80A80000").let { h -> val d = buildGpoData(findTag(fci, 0x9F38)); h + byteArrayOf(d.size.toByte()) + d + byteArrayOf(0) }
            r = iso.transceive(gpo)
            info.raw.append("GPO -> ${hex(r)}\n")
            if (!sw9000(r)) continue
            val gresp = r.copyOfRange(0, r.size - 2)
            var afl = findTag(gresp, 0x94)
            if (afl == null) findTag(gresp, 0x80)?.let { if (it.size > 2) afl = it.copyOfRange(2, it.size) }  // format 1
            val recs = ArrayList<ByteArray>()
            afl?.let { a ->
                var k = 0
                while (k + 4 <= a.size) {
                    val sfi = (a[k].toInt() and 0xFF) shr 3
                    val first = a[k + 1].toInt() and 0xFF
                    val last = a[k + 2].toInt() and 0xFF
                    k += 4
                    for (rec in first..last) {
                        val p2 = ((sfi shl 3) or 4)
                        val rr = iso.transceive(byteArrayOf(0x00, 0xB2.toByte(), rec.toByte(), p2.toByte(), 0x00))
                        info.raw.append("READ sfi$sfi rec$rec -> ${hex(rr)}\n")
                        if (sw9000(rr)) recs.add(rr.copyOfRange(0, rr.size - 2))
                    }
                }
            }
            for (b in recs + listOf(gresp, fci)) {
                if (info.pan.isEmpty()) findTag(b, 0x5A)?.let { info.pan = panFromBcd(it) }
                if (info.expiry.isEmpty()) findTag(b, 0x5F24)?.let { info.expiry = expiryYYMMDD(it) }
                if (info.effective.isEmpty()) findTag(b, 0x5F25)?.let { info.effective = expiryYYMMDD(it) }
                if (info.cardholder.isEmpty()) findTag(b, 0x5F20)?.let { val s = String(it).trim(); if (s.isNotEmpty()) info.cardholder = s }
                findTag(b, 0x57)?.let {
                    if (info.track2.isEmpty()) info.track2 = hex(it)
                    if (info.pan.isEmpty()) info.pan = panFromTrack2(it)
                    if (info.expiry.isEmpty()) info.expiry = expiryFromTrack2(it)
                }
                if (info.panSeq.isEmpty()) findTag(b, 0x5F34)?.let { info.panSeq = hex(it) }
                if (info.country.isEmpty()) findTag(b, 0x5F28)?.let { info.country = country(it) }
                if (info.currency.isEmpty()) findTag(b, 0x9F42)?.let { info.currency = currency(it) }
            }
            if (info.pan.isNotEmpty()) { info.ok = true; break }
        }
        return info
    }

    // Pretty multi-line summary for the log view.
    fun format(info: Info): String {
        if (!info.ok && info.pan.isEmpty()) return "No EMV data read (card removed too soon?)"
        val sb = StringBuilder()
        val panSpaced = info.pan.chunked(4).joinToString(" ")
        sb.append("Scheme   : ${info.scheme}\n")
        sb.append("PAN      : $panSpaced\n")
        if (info.expiry.isNotEmpty())     sb.append("Expiry   : ${info.expiry}\n")
        if (info.effective.isNotEmpty())  sb.append("Effective: ${info.effective}\n")
        if (info.cardholder.isNotEmpty()) sb.append("Name     : ${info.cardholder}\n")
        if (info.appLabel.isNotEmpty())   sb.append("App      : ${info.appLabel}\n")
        if (info.aid.isNotEmpty())        sb.append("AID      : ${info.aid}\n")
        if (info.panSeq.isNotEmpty())     sb.append("PAN seq  : ${info.panSeq}\n")
        if (info.country.isNotEmpty())    sb.append("Country  : ${info.country}\n")
        if (info.currency.isNotEmpty())   sb.append("Currency : ${info.currency}\n")
        if (info.track2.isNotEmpty())     sb.append("Track2   : ${info.track2}\n")
        return sb.toString().trimEnd()
    }
}
