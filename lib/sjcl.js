var sjcl = {
  cipher: {},
  hash: {},
  keyexchange: {},
  mode: {},
  misc: {},
  codec: {},
  exception: {
    corrupt: function (t) {
      this.toString = function () {
        return "CORRUPT: " + this.message
      }, this.message = t
    },
    invalid: function (t) {
      this.toString = function () {
        return "INVALID: " + this.message
      }, this.message = t
    },
    bug: function (t) {
      this.toString = function () {
        return "BUG: " + this.message
      }, this.message = t
    },
    notReady: function (t) {
      this.toString = function () {
        return "NOT READY: " + this.message
      }, this.message = t
    }
  }
};
"undefined" != typeof module && module.exports && (module.exports = sjcl), sjcl.cipher.aes = function (t) {
    this._tables[0][0][0] || this._precompute();
    var e, a, i, n, o, r = this._tables[0][4],
      s = this._tables[1],
      u = t.length,
      c = 1;
    if (4 !== u && 6 !== u && 8 !== u) throw new sjcl.exception.invalid("invalid aes key size");
    for (this._key = [n = t.slice(0), o = []], e = u; 4 * u + 28 > e; e++) i = n[e - 1], (e % u === 0 || 8 === u && e % u === 4) && (i = r[i >>> 24] << 24 ^ r[i >> 16 & 255] << 16 ^ r[i >> 8 & 255] << 8 ^ r[255 & i], e % u === 0 && (i = i << 8 ^ i >>> 24 ^ c << 24, c = c << 1 ^ 283 * (c >> 7))), n[e] = n[e - u] ^ i;
    for (a = 0; e; a++, e--) i = n[3 & a ? e : e - 4], 4 >= e || 4 > a ? o[a] = i : o[a] = s[0][r[i >>> 24]] ^ s[1][r[i >> 16 & 255]] ^ s[2][r[i >> 8 & 255]] ^ s[3][r[255 & i]]
  }, sjcl.cipher.aes.prototype = {
    encrypt: function (t) {
      return this._crypt(t, 0)
    },
    decrypt: function (t) {
      return this._crypt(t, 1)
    },
    _tables: [
      [
        [],
        [],
        [],
        [],
        []
      ],
      [
        [],
        [],
        [],
        [],
        []
      ]
    ],
    _precompute: function () {
      var t, e, a, i, n, o, r, s, u, c = this._tables[0],
        l = this._tables[1],
        h = c[4],
        f = l[4],
        m = [],
        d = [];
      for (t = 0; 256 > t; t++) d[(m[t] = t << 1 ^ 283 * (t >> 7)) ^ t] = t;
      for (e = a = 0; !h[e]; e ^= i || 1, a = d[a] || 1)
        for (r = a ^ a << 1 ^ a << 2 ^ a << 3 ^ a << 4, r = r >> 8 ^ 255 & r ^ 99, h[e] = r, f[r] = e, o = m[n = m[i = m[e]]], u = 16843009 * o ^ 65537 * n ^ 257 * i ^ 16843008 * e, s = 257 * m[r] ^ 16843008 * r, t = 0; 4 > t; t++) c[t][e] = s = s << 24 ^ s >>> 8, l[t][r] = u = u << 24 ^ u >>> 8;
      for (t = 0; 5 > t; t++) c[t] = c[t].slice(0), l[t] = l[t].slice(0)
    },
    _crypt: function (t, e) {
      if (4 !== t.length) throw new sjcl.exception.invalid("invalid aes block size");
      var a, i, n, o, r = this._key[e],
        s = t[0] ^ r[0],
        u = t[e ? 3 : 1] ^ r[1],
        c = t[2] ^ r[2],
        l = t[e ? 1 : 3] ^ r[3],
        h = r.length / 4 - 2,
        f = 4,
        m = [0, 0, 0, 0],
        d = this._tables[e],
        p = d[0],
        g = d[1],
        k = d[2],
        y = d[3],
        v = d[4];
      for (o = 0; h > o; o++) a = p[s >>> 24] ^ g[u >> 16 & 255] ^ k[c >> 8 & 255] ^ y[255 & l] ^ r[f], i = p[u >>> 24] ^ g[c >> 16 & 255] ^ k[l >> 8 & 255] ^ y[255 & s] ^ r[f + 1], n = p[c >>> 24] ^ g[l >> 16 & 255] ^ k[s >> 8 & 255] ^ y[255 & u] ^ r[f + 2], l = p[l >>> 24] ^ g[s >> 16 & 255] ^ k[u >> 8 & 255] ^ y[255 & c] ^ r[f + 3], f += 4, s = a, u = i, c = n;
      for (o = 0; 4 > o; o++) m[e ? 3 & -o : o] = v[s >>> 24] << 24 ^ v[u >> 16 & 255] << 16 ^ v[c >> 8 & 255] << 8 ^ v[255 & l] ^ r[f++], a = s, s = u, u = c, c = l, l = a;
      return m
    }
  }, sjcl.bitArray = {
    bitSlice: function (t, e, a) {
      return t = sjcl.bitArray._shiftRight(t.slice(e / 32), 32 - (31 & e)).slice(1), void 0 === a ? t : sjcl.bitArray.clamp(t, a - e)
    },
    extract: function (t, e, a) {
      var i, n = Math.floor(-e - a & 31);
      return i = -32 & (e + a - 1 ^ e) ? t[e / 32 | 0] << 32 - n ^ t[e / 32 + 1 | 0] >>> n : t[e / 32 | 0] >>> n, i & (1 << a) - 1
    },
    concat: function (t, e) {
      if (0 === t.length || 0 === e.length) return t.concat(e);
      var a = t[t.length - 1],
        i = sjcl.bitArray.getPartial(a);
      return 32 === i ? t.concat(e) : sjcl.bitArray._shiftRight(e, i, 0 | a, t.slice(0, t.length - 1))
    },
    bitLength: function (t) {
      var e, a = t.length;
      return 0 === a ? 0 : (e = t[a - 1], 32 * (a - 1) + sjcl.bitArray.getPartial(e))
    },
    clamp: function (t, e) {
      if (32 * t.length < e) return t;
      t = t.slice(0, Math.ceil(e / 32));
      var a = t.length;
      return e = 31 & e, a > 0 && e && (t[a - 1] = sjcl.bitArray.partial(e, t[a - 1] & 2147483648 >> e - 1, 1)), t
    },
    partial: function (t, e, a) {
      return 32 === t ? e : (a ? 0 | e : e << 32 - t) + 1099511627776 * t
    },
    getPartial: function (t) {
      return Math.round(t / 1099511627776) || 32
    },
    equal: function (t, e) {
      if (sjcl.bitArray.bitLength(t) !== sjcl.bitArray.bitLength(e)) return !1;
      var a, i = 0;
      for (a = 0; a < t.length; a++) i |= t[a] ^ e[a];
      return 0 === i
    },
    _shiftRight: function (t, e, a, i) {
      var n, o, r = 0;
      for (void 0 === i && (i = []); e >= 32; e -= 32) i.push(a), a = 0;
      if (0 === e) return i.concat(t);
      for (n = 0; n < t.length; n++) i.push(a | t[n] >>> e), a = t[n] << 32 - e;
      return r = t.length ? t[t.length - 1] : 0, o = sjcl.bitArray.getPartial(r), i.push(sjcl.bitArray.partial(e + o & 31, e + o > 32 ? a : i.pop(), 1)), i
    },
    _xor4: function (t, e) {
      return [t[0] ^ e[0], t[1] ^ e[1], t[2] ^ e[2], t[3] ^ e[3]]
    }
  }, sjcl.codec.utf8String = {
    fromBits: function (t) {
      var e, a, i = "",
        n = sjcl.bitArray.bitLength(t);
      for (e = 0; n / 8 > e; e++) 0 === (3 & e) && (a = t[e / 4]), i += String.fromCharCode(a >>> 24), a <<= 8;
      return decodeURIComponent(escape(i))
    },
    toBits: function (t) {
      t = unescape(encodeURIComponent(t));
      var e, a = [],
        i = 0;
      for (e = 0; e < t.length; e++) i = i << 8 | t.charCodeAt(e), 3 === (3 & e) && (a.push(i), i = 0);
      return 3 & e && a.push(sjcl.bitArray.partial(8 * (3 & e), i)), a
    }
  }, sjcl.codec.hex = {
    fromBits: function (t) {
      var e, a = "";
      for (e = 0; e < t.length; e++) a += ((0 | t[e]) + 0xf00000000000).toString(16).substr(4);
      return a.substr(0, sjcl.bitArray.bitLength(t) / 4)
    },
    toBits: function (t) {
      var e, a, i = [];
      for (t = t.replace(/\s|0x/g, ""), a = t.length, t += "00000000", e = 0; e < t.length; e += 8) i.push(0 ^ parseInt(t.substr(e, 8), 16));
      return sjcl.bitArray.clamp(i, 4 * a)
    }
  }, sjcl.codec.base64 = {
    _chars: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
    fromBits: function (t, e, a) {
      var i, n = "",
        o = 0,
        r = sjcl.codec.base64._chars,
        s = 0,
        u = sjcl.bitArray.bitLength(t);
      for (a && (r = r.substr(0, 62) + "-_"), i = 0; 6 * n.length < u;) n += r.charAt((s ^ t[i] >>> o) >>> 26), 6 > o ? (s = t[i] << 6 - o, o += 26, i++) : (s <<= 6, o -= 6);
      for (; 3 & n.length && !e;) n += "=";
      return n
    },
    toBits: function (t, e) {
      t = t.replace(/\s|=/g, "");
      var a, i, n = [],
        o = 0,
        r = sjcl.codec.base64._chars,
        s = 0;
      for (e && (r = r.substr(0, 62) + "-_"), a = 0; a < t.length; a++) {
        if (i = r.indexOf(t.charAt(a)), 0 > i) throw new sjcl.exception.invalid("this isn't base64!");
        o > 26 ? (o -= 26, n.push(s ^ i >>> o), s = i << 32 - o) : (o += 6, s ^= i << 32 - o)
      }
      return 56 & o && n.push(sjcl.bitArray.partial(56 & o, s, 1)), n
    }
  }, sjcl.codec.base64url = {
    fromBits: function (t) {
      return sjcl.codec.base64.fromBits(t, 1, 1)
    },
    toBits: function (t) {
      return sjcl.codec.base64.toBits(t, 1)
    }
  }, sjcl.codec.bytes = {
    fromBits: function (t) {
      var e, a, i = [],
        n = sjcl.bitArray.bitLength(t);
      for (e = 0; n / 8 > e; e++) 0 === (3 & e) && (a = t[e / 4]), i.push(a >>> 24), a <<= 8;
      return i
    },
    toBits: function (t) {
      var e, a = [],
        i = 0;
      for (e = 0; e < t.length; e++) i = i << 8 | t[e], 3 === (3 & e) && (a.push(i), i = 0);
      return 3 & e && a.push(sjcl.bitArray.partial(8 * (3 & e), i)), a
    }
  }, sjcl.hash.sha256 = function (t) {
    this._key[0] || this._precompute(), t ? (this._h = t._h.slice(0), this._buffer = t._buffer.slice(0), this._length = t._length) : this.reset()
  }, sjcl.hash.sha256.hash = function (t) {
    return (new sjcl.hash.sha256).update(t).finalize()
  }, sjcl.hash.sha256.prototype = {
    blockSize: 512,
    reset: function () {
      return this._h = this._init.slice(0), this._buffer = [], this._length = 0, this
    },
    update: function (t) {
      "string" == typeof t && (t = sjcl.codec.utf8String.toBits(t));
      var e, a = this._buffer = sjcl.bitArray.concat(this._buffer, t),
        i = this._length,
        n = this._length = i + sjcl.bitArray.bitLength(t);
      for (e = 512 + i & -512; n >= e; e += 512) this._block(a.splice(0, 16));
      return this
    },
    finalize: function () {
      var t, e = this._buffer,
        a = this._h;
      for (e = sjcl.bitArray.concat(e, [sjcl.bitArray.partial(1, 1)]), t = e.length + 2; 15 & t; t++) e.push(0);
      for (e.push(Math.floor(this._length / 4294967296)), e.push(0 | this._length); e.length;) this._block(e.splice(0, 16));
      return this.reset(), a
    },
    _init: [],
    _key: [],
    _precompute: function () {
      function t(t) {
        return 4294967296 * (t - Math.floor(t)) | 0
      }
      var e, a = 0,
        i = 2;
      t: for (; 64 > a; i++) {
        for (e = 2; i >= e * e; e++)
          if (i % e === 0) continue t;
        8 > a && (this._init[a] = t(Math.pow(i, .5))), this._key[a] = t(Math.pow(i, 1 / 3)), a++
      }
    },
    _block: function (t) {
      var e, a, i, n, o = t.slice(0),
        r = this._h,
        s = this._key,
        u = r[0],
        c = r[1],
        l = r[2],
        h = r[3],
        f = r[4],
        m = r[5],
        d = r[6],
        p = r[7];
      for (e = 0; 64 > e; e++) 16 > e ? a = o[e] : (i = o[e + 1 & 15], n = o[e + 14 & 15], a = o[15 & e] = (i >>> 7 ^ i >>> 18 ^ i >>> 3 ^ i << 25 ^ i << 14) + (n >>> 17 ^ n >>> 19 ^ n >>> 10 ^ n << 15 ^ n << 13) + o[15 & e] + o[e + 9 & 15] | 0), a = a + p + (f >>> 6 ^ f >>> 11 ^ f >>> 25 ^ f << 26 ^ f << 21 ^ f << 7) + (d ^ f & (m ^ d)) + s[e], p = d, d = m, m = f, f = h + a | 0, h = l, l = c, c = u, u = a + (c & l ^ h & (c ^ l)) + (c >>> 2 ^ c >>> 13 ^ c >>> 22 ^ c << 30 ^ c << 19 ^ c << 10) | 0;
      r[0] = r[0] + u | 0, r[1] = r[1] + c | 0, r[2] = r[2] + l | 0, r[3] = r[3] + h | 0, r[4] = r[4] + f | 0, r[5] = r[5] + m | 0, r[6] = r[6] + d | 0, r[7] = r[7] + p | 0
    }
  }, sjcl.hash.sha512 = function (t) {
    this._key[0] || this._precompute(), t ? (this._h = t._h.slice(0), this._buffer = t._buffer.slice(0), this._length = t._length) : this.reset()
  }, sjcl.hash.sha512.hash = function (t) {
    return (new sjcl.hash.sha512).update(t).finalize()
  }, sjcl.hash.sha512.prototype = {
    blockSize: 1024,
    reset: function () {
      return this._h = this._init.slice(0), this._buffer = [], this._length = 0, this
    },
    update: function (t) {
      "string" == typeof t && (t = sjcl.codec.utf8String.toBits(t));
      var e, a = this._buffer = sjcl.bitArray.concat(this._buffer, t),
        i = this._length,
        n = this._length = i + sjcl.bitArray.bitLength(t);
      for (e = 1024 + i & -1024; n >= e; e += 1024) this._block(a.splice(0, 32));
      return this
    },
    finalize: function () {
      var t, e = this._buffer,
        a = this._h;
      for (e = sjcl.bitArray.concat(e, [sjcl.bitArray.partial(1, 1)]), t = e.length + 4; 31 & t; t++) e.push(0);
      for (e.push(0), e.push(0), e.push(Math.floor(this._length / 4294967296)), e.push(0 | this._length); e.length;) this._block(e.splice(0, 32));
      return this.reset(), a
    },
    _init: [],
    _initr: [12372232, 13281083, 9762859, 1914609, 15106769, 4090911, 4308331, 8266105],
    _key: [],
    _keyr: [2666018, 15689165, 5061423, 9034684, 4764984, 380953, 1658779, 7176472, 197186, 7368638, 14987916, 16757986, 8096111, 1480369, 13046325, 6891156, 15813330, 5187043, 9229749, 11312229, 2818677, 10937475, 4324308, 1135541, 6741931, 11809296, 16458047, 15666916, 11046850, 698149, 229999, 945776, 13774844, 2541862, 12856045, 9810911, 11494366, 7844520, 15576806, 8533307, 15795044, 4337665, 16291729, 5553712, 15684120, 6662416, 7413802, 12308920, 13816008, 4303699, 9366425, 10176680, 13195875, 4295371, 6546291, 11712675, 15708924, 1519456, 15772530, 6568428, 6495784, 8568297, 13007125, 7492395, 2515356, 12632583, 14740254, 7262584, 1535930, 13146278, 16321966, 1853211, 294276, 13051027, 13221564, 1051980, 4080310, 6651434, 14088940, 4675607],
    _precompute: function () {
      function t(t) {
        return 4294967296 * (t - Math.floor(t)) | 0
      }

      function e(t) {
        return 1099511627776 * (t - Math.floor(t)) & 255
      }
      var a, i = 0,
        n = 2;
      t: for (; 80 > i; n++) {
        for (a = 2; n >= a * a; a++)
          if (n % a === 0) continue t;
        8 > i && (this._init[2 * i] = t(Math.pow(n, .5)), this._init[2 * i + 1] = e(Math.pow(n, .5)) << 24 | this._initr[i]), this._key[2 * i] = t(Math.pow(n, 1 / 3)), this._key[2 * i + 1] = e(Math.pow(n, 1 / 3)) << 24 | this._keyr[i], i++
      }
    },
    _block: function (t) {
      var e, a, i, n = t.slice(0),
        o = this._h,
        r = this._key,
        s = o[0],
        u = o[1],
        c = o[2],
        l = o[3],
        h = o[4],
        f = o[5],
        m = o[6],
        d = o[7],
        p = o[8],
        g = o[9],
        k = o[10],
        y = o[11],
        v = o[12],
        b = o[13],
        w = o[14],
        x = o[15],
        j = s,
        _ = u,
        A = c,
        B = l,
        T = h,
        z = f,
        S = m,
        E = d,
        C = p,
        D = g,
        N = k,
        M = y,
        I = v,
        R = b,
        F = w,
        O = x;
      for (e = 0; 80 > e; e++) {
        if (16 > e) a = n[2 * e], i = n[2 * e + 1];
        else {
          var L = n[2 * (e - 15)],
            q = n[2 * (e - 15) + 1],
            P = (q << 31 | L >>> 1) ^ (q << 24 | L >>> 8) ^ L >>> 7,
            H = (L << 31 | q >>> 1) ^ (L << 24 | q >>> 8) ^ (L << 25 | q >>> 7),
            U = n[2 * (e - 2)],
            V = n[2 * (e - 2) + 1],
            W = (V << 13 | U >>> 19) ^ (U << 3 | V >>> 29) ^ U >>> 6,
            $ = (U << 13 | V >>> 19) ^ (V << 3 | U >>> 29) ^ (U << 26 | V >>> 6),
            X = n[2 * (e - 7)],
            K = n[2 * (e - 7) + 1],
            J = n[2 * (e - 16)],
            G = n[2 * (e - 16) + 1];
          i = H + K, a = P + X + (H >>> 0 > i >>> 0 ? 1 : 0), i += $, a += W + ($ >>> 0 > i >>> 0 ? 1 : 0), i += G, a += J + (G >>> 0 > i >>> 0 ? 1 : 0)
        }
        n[2 * e] = a |= 0, n[2 * e + 1] = i |= 0;
        var Q = C & N ^ ~C & I,
          Y = D & M ^ ~D & R,
          Z = j & A ^ j & T ^ A & T,
          tt = _ & B ^ _ & z ^ B & z,
          et = (_ << 4 | j >>> 28) ^ (j << 30 | _ >>> 2) ^ (j << 25 | _ >>> 7),
          at = (j << 4 | _ >>> 28) ^ (_ << 30 | j >>> 2) ^ (_ << 25 | j >>> 7),
          it = (D << 18 | C >>> 14) ^ (D << 14 | C >>> 18) ^ (C << 23 | D >>> 9),
          nt = (C << 18 | D >>> 14) ^ (C << 14 | D >>> 18) ^ (D << 23 | C >>> 9),
          ot = r[2 * e],
          rt = r[2 * e + 1],
          st = O + nt,
          ut = F + it + (O >>> 0 > st >>> 0 ? 1 : 0);
        st += Y, ut += Q + (Y >>> 0 > st >>> 0 ? 1 : 0), st += rt, ut += ot + (rt >>> 0 > st >>> 0 ? 1 : 0), st += i, ut += a + (i >>> 0 > st >>> 0 ? 1 : 0);
        var ct = at + tt,
          lt = et + Z + (at >>> 0 > ct >>> 0 ? 1 : 0);
        F = I, O = R, I = N, R = M, N = C, M = D, D = E + st | 0, C = S + ut + (E >>> 0 > D >>> 0 ? 1 : 0) | 0, S = T, E = z, T = A, z = B, A = j, B = _, _ = st + ct | 0, j = ut + lt + (st >>> 0 > _ >>> 0 ? 1 : 0) | 0
      }
      u = o[1] = u + _ | 0, o[0] = s + j + (_ >>> 0 > u >>> 0 ? 1 : 0) | 0, l = o[3] = l + B | 0, o[2] = c + A + (B >>> 0 > l >>> 0 ? 1 : 0) | 0, f = o[5] = f + z | 0, o[4] = h + T + (z >>> 0 > f >>> 0 ? 1 : 0) | 0, d = o[7] = d + E | 0, o[6] = m + S + (E >>> 0 > d >>> 0 ? 1 : 0) | 0, g = o[9] = g + D | 0, o[8] = p + C + (D >>> 0 > g >>> 0 ? 1 : 0) | 0, y = o[11] = y + M | 0, o[10] = k + N + (M >>> 0 > y >>> 0 ? 1 : 0) | 0, b = o[13] = b + R | 0, o[12] = v + I + (R >>> 0 > b >>> 0 ? 1 : 0) | 0, x = o[15] = x + O | 0, o[14] = w + F + (O >>> 0 > x >>> 0 ? 1 : 0) | 0
    }
  }, sjcl.hash.sha1 = function (t) {
    t ? (this._h = t._h.slice(0), this._buffer = t._buffer.slice(0), this._length = t._length) : this.reset()
  }, sjcl.hash.sha1.hash = function (t) {
    return (new sjcl.hash.sha1).update(t).finalize()
  }, sjcl.hash.sha1.prototype = {
    blockSize: 512,
    reset: function () {
      return this._h = this._init.slice(0), this._buffer = [], this._length = 0, this
    },
    update: function (t) {
      "string" == typeof t && (t = sjcl.codec.utf8String.toBits(t));
      var e, a = this._buffer = sjcl.bitArray.concat(this._buffer, t),
        i = this._length,
        n = this._length = i + sjcl.bitArray.bitLength(t);
      for (e = this.blockSize + i & -this.blockSize; n >= e; e += this.blockSize) this._block(a.splice(0, 16));
      return this
    },
    finalize: function () {
      var t, e = this._buffer,
        a = this._h;
      for (e = sjcl.bitArray.concat(e, [sjcl.bitArray.partial(1, 1)]), t = e.length + 2; 15 & t; t++) e.push(0);
      for (e.push(Math.floor(this._length / 4294967296)), e.push(0 | this._length); e.length;) this._block(e.splice(0, 16));
      return this.reset(), a
    },
    _init: [1732584193, 4023233417, 2562383102, 271733878, 3285377520],
    _key: [1518500249, 1859775393, 2400959708, 3395469782],
    _f: function (t, e, a, i) {
      return 19 >= t ? e & a | ~e & i : 39 >= t ? e ^ a ^ i : 59 >= t ? e & a | e & i | a & i : 79 >= t ? e ^ a ^ i : null
    },
    _S: function (t, e) {
      return e << t | e >>> 32 - t
    },
    _block: function (t) {
      {
        var e, a, i, n, o, r, s, u = t.slice(0),
          c = this._h;
        this._key
      }
      for (i = c[0], n = c[1], o = c[2], r = c[3], s = c[4], e = 0; 79 >= e; e++) e >= 16 && (u[e] = this._S(1, u[e - 3] ^ u[e - 8] ^ u[e - 14] ^ u[e - 16])), a = this._S(5, i) + this._f(e, n, o, r) + s + u[e] + this._key[Math.floor(e / 20)] | 0, s = r, r = o, o = this._S(30, n), n = i, i = a;
      c[0] = c[0] + i | 0, c[1] = c[1] + n | 0, c[2] = c[2] + o | 0, c[3] = c[3] + r | 0, c[4] = c[4] + s | 0
    }
  }, sjcl.mode.ccm = {
    name: "ccm",
    encrypt: function (t, e, a, i, n) {
      var o, r, s = e.slice(0),
        u = sjcl.bitArray,
        c = u.bitLength(a) / 8,
        l = u.bitLength(s) / 8;
      if (n = n || 64, i = i || [], 7 > c) throw new sjcl.exception.invalid("ccm: iv must be at least 7 bytes");
      for (o = 2; 4 > o && l >>> 8 * o; o++);
      return 15 - c > o && (o = 15 - c), a = u.clamp(a, 8 * (15 - o)), r = sjcl.mode.ccm._computeTag(t, e, a, i, n, o), s = sjcl.mode.ccm._ctrMode(t, s, a, r, n, o), u.concat(s.data, s.tag)
    },
    decrypt: function (t, e, a, i, n) {
      n = n || 64, i = i || [];
      var o, r, s = sjcl.bitArray,
        u = s.bitLength(a) / 8,
        c = s.bitLength(e),
        l = s.clamp(e, c - n),
        h = s.bitSlice(e, c - n);
      if (c = (c - n) / 8, 7 > u) throw new sjcl.exception.invalid("ccm: iv must be at least 7 bytes");
      for (o = 2; 4 > o && c >>> 8 * o; o++);
      if (15 - u > o && (o = 15 - u), a = s.clamp(a, 8 * (15 - o)), l = sjcl.mode.ccm._ctrMode(t, l, a, h, n, o), r = sjcl.mode.ccm._computeTag(t, l.data, a, i, n, o), !s.equal(l.tag, r)) throw new sjcl.exception.corrupt("ccm: tag doesn't match");
      return l.data
    },
    _computeTag: function (t, e, a, i, n, o) {
      var r, s, u, c = [],
        l = sjcl.bitArray,
        h = l._xor4;
      if (n /= 8, n % 2 || 4 > n || n > 16) throw new sjcl.exception.invalid("ccm: invalid tag length");
      if (i.length > 4294967295 || e.length > 4294967295) throw new sjcl.exception.bug("ccm: can't deal with 4GiB or more data");
      if (r = [l.partial(8, (i.length ? 64 : 0) | n - 2 << 2 | o - 1)], r = l.concat(r, a), r[3] |= l.bitLength(e) / 8, r = t.encrypt(r), i.length)
        for (s = l.bitLength(i) / 8, 65279 >= s ? c = [l.partial(16, s)] : 4294967295 >= s && (c = l.concat([l.partial(16, 65534)], [s])), c = l.concat(c, i), u = 0; u < c.length; u += 4) r = t.encrypt(h(r, c.slice(u, u + 4).concat([0, 0, 0])));
      for (u = 0; u < e.length; u += 4) r = t.encrypt(h(r, e.slice(u, u + 4).concat([0, 0, 0])));
      return l.clamp(r, 8 * n)
    },
    _ctrMode: function (t, e, a, i, n, o) {
      var r, s, u, c = sjcl.bitArray,
        l = c._xor4,
        h = e.length,
        f = c.bitLength(e);
      if (u = c.concat([c.partial(8, o - 1)], a).concat([0, 0, 0]).slice(0, 4), i = c.bitSlice(l(i, t.encrypt(u)), 0, n), !h) return {
        tag: i,
        data: []
      };
      for (s = 0; h > s; s += 4) u[3]++, r = t.encrypt(u), e[s] ^= r[0], e[s + 1] ^= r[1], e[s + 2] ^= r[2], e[s + 3] ^= r[3];
      return {
        tag: i,
        data: c.clamp(e, f)
      }
    }
  }, sjcl.mode.ctr = {
    name: "ctr",
    encrypt: function (t, e, a, i) {
      {
        var n = e.slice(0),
          o = sjcl.bitArray,
          r = o.bitLength(a) / 8;
        o.bitLength(n) / 8
      }
      if (i && i.length) throw new sjcl.exception.invalid("ctr: can't authenticate data");
      if (8 > r) throw new sjcl.exception.invalid("ctr: iv must be at least 64-bits (was " + r + ")");
      return a = o.clamp(a, 64), n = sjcl.mode.ctr._ctrMode(t, n, a), n.data
    },
    decrypt: function (t, e, a, i) {
      var n = sjcl.bitArray,
        o = n.bitLength(a) / 8,
        r = n.bitLength(e),
        s = n.clamp(e, r);
      if (i && i.length) throw new sjcl.exception.invalid("ctr: can't authenticate data");
      if (r /= 8, 8 != o) throw new sjcl.exception.invalid("ctr: iv must be 64-bits");
      return a = n.clamp(a, 64), s = sjcl.mode.ctr._ctrMode(t, s, a), s.data
    },
    _ctrMode: function (t, e, a) {
      var i, n, o, r = sjcl.bitArray,
        s = (r._xor4, e.length),
        u = r.bitLength(e);
      if (o = r.concat(a, [0, 0]), !s) return {
        data: []
      };
      for (n = 0; s > n; n += 4) i = t.encrypt(o), e[n] ^= i[0], e[n + 1] ^= i[1], e[n + 2] ^= i[2], e[n + 3] ^= i[3], o[3]++;
      return {
        data: r.clamp(e, u)
      }
    }
  }, sjcl.mode.cbc = {
    name: "cbc",
    encrypt: function (t, e, a, i) {
      if (i && i.length) throw new sjcl.exception.invalid("cbc can't authenticate data");
      if (128 !== sjcl.bitArray.bitLength(a)) throw new sjcl.exception.invalid("cbc iv must be 128 bits");
      var n, o = sjcl.bitArray,
        r = o._xor4,
        s = o.bitLength(e),
        u = 0,
        c = [];
      if (7 & s) throw new sjcl.exception.invalid("pkcs#5 padding only works for multiples of a byte");
      for (n = 0; s >= u + 128; n += 4, u += 128) a = t.encrypt(r(a, e.slice(n, n + 4))), c.splice(n, 0, a[0], a[1], a[2], a[3]);
      return s = 16843009 * (16 - (s >> 3 & 15)), a = t.encrypt(r(a, o.concat(e, [s, s, s, s]).slice(n, n + 4))), c.splice(n, 0, a[0], a[1], a[2], a[3]), c
    },
    decrypt: function (t, e, a, i) {
      if (i && i.length) throw new sjcl.exception.invalid("cbc can't authenticate data");
      if (128 !== sjcl.bitArray.bitLength(a)) throw new sjcl.exception.invalid("cbc iv must be 128 bits");
      if (127 & sjcl.bitArray.bitLength(e) || !e.length) throw new sjcl.exception.corrupt("cbc ciphertext must be a positive multiple of the block size");
      var n, o, r, s = sjcl.bitArray,
        u = s._xor4,
        c = [];
      for (i = i || [], n = 0; n < e.length; n += 4) o = e.slice(n, n + 4), r = u(a, t.decrypt(o)), c.splice(n, 0, r[0], r[1], r[2], r[3]), a = o;
      if (o = 255 & c[n - 1], 0 == o || o > 16) throw new sjcl.exception.corrupt("pkcs#5 padding corrupt");
      if (r = 16843009 * o, !s.equal(s.bitSlice([r, r, r, r], 0, 8 * o), s.bitSlice(c, 32 * c.length - 8 * o, 32 * c.length))) throw new sjcl.exception.corrupt("pkcs#5 padding corrupt");
      return s.bitSlice(c, 0, 32 * c.length - 8 * o)
    }
  }, sjcl.mode.ocb2 = {
    name: "ocb2",
    encrypt: function (t, e, a, i, n, o) {
      if (128 !== sjcl.bitArray.bitLength(a)) throw new sjcl.exception.invalid("ocb iv must be 128 bits");
      var r, s, u, c, l = sjcl.mode.ocb2._times2,
        h = sjcl.bitArray,
        f = h._xor4,
        m = [0, 0, 0, 0],
        d = l(t.encrypt(a)),
        p = [];
      for (i = i || [], n = n || 64, r = 0; r + 4 < e.length; r += 4) s = e.slice(r, r + 4), m = f(m, s), p = p.concat(f(d, t.encrypt(f(d, s)))), d = l(d);
      return s = e.slice(r), u = h.bitLength(s), c = t.encrypt(f(d, [0, 0, 0, u])), s = h.clamp(f(s.concat([0, 0, 0]), c), u), m = f(m, f(s.concat([0, 0, 0]), c)), m = t.encrypt(f(m, f(d, l(d)))), i.length && (m = f(m, o ? i : sjcl.mode.ocb2.pmac(t, i))), p.concat(h.concat(s, h.clamp(m, n)))
    },
    decrypt: function (t, e, a, i, n, o) {
      if (128 !== sjcl.bitArray.bitLength(a)) throw new sjcl.exception.invalid("ocb iv must be 128 bits");
      n = n || 64;
      var r, s, u, c, l = sjcl.mode.ocb2._times2,
        h = sjcl.bitArray,
        f = h._xor4,
        m = [0, 0, 0, 0],
        d = l(t.encrypt(a)),
        p = sjcl.bitArray.bitLength(e) - n,
        g = [];
      for (i = i || [], r = 0; p / 32 > r + 4; r += 4) s = f(d, t.decrypt(f(d, e.slice(r, r + 4)))), m = f(m, s), g = g.concat(s), d = l(d);
      if (u = p - 32 * r, c = t.encrypt(f(d, [0, 0, 0, u])), s = f(c, h.clamp(e.slice(r), u).concat([0, 0, 0])), m = f(m, s), m = t.encrypt(f(m, f(d, l(d)))), i.length && (m = f(m, o ? i : sjcl.mode.ocb2.pmac(t, i))), !h.equal(h.clamp(m, n), h.bitSlice(e, p))) throw new sjcl.exception.corrupt("ocb: tag doesn't match");
      return g.concat(h.clamp(s, u))
    },
    pmac: function (t, e) {
      var a, i, n = sjcl.mode.ocb2._times2,
        o = sjcl.bitArray,
        r = o._xor4,
        s = [0, 0, 0, 0],
        u = t.encrypt([0, 0, 0, 0]);
      for (u = r(u, n(n(u))), a = 0; a + 4 < e.length; a += 4) u = n(u), s = r(s, t.encrypt(r(u, e.slice(a, a + 4))));
      return i = e.slice(a), o.bitLength(i) < 128 && (u = r(u, n(u)), i = o.concat(i, [-2147483648, 0, 0, 0])), s = r(s, i), t.encrypt(r(n(r(u, n(u))), s))
    },
    _times2: function (t) {
      return [t[0] << 1 ^ t[1] >>> 31, t[1] << 1 ^ t[2] >>> 31, t[2] << 1 ^ t[3] >>> 31, t[3] << 1 ^ 135 * (t[0] >>> 31)]
    }
  }, sjcl.mode.gcm = {
    name: "gcm",
    encrypt: function (t, e, a, i, n) {
      var o, r = e.slice(0),
        s = sjcl.bitArray;
      return n = n || 128, i = i || [], o = sjcl.mode.gcm._ctrMode(!0, t, r, i, a, n), s.concat(o.data, o.tag)
    },
    decrypt: function (t, e, a, i, n) {
      var o, r, s = e.slice(0),
        u = sjcl.bitArray,
        c = u.bitLength(s);
      if (n = n || 128, i = i || [], c >= n ? (r = u.bitSlice(s, c - n), s = u.bitSlice(s, 0, c - n)) : (r = s, s = []), o = sjcl.mode.gcm._ctrMode(!1, t, s, i, a, n), !u.equal(o.tag, r)) throw new sjcl.exception.corrupt("gcm: tag doesn't match");
      return o.data
    },
    _galoisMultiply: function (t, e) {
      var a, i, n, o, r, s, u = sjcl.bitArray,
        c = u._xor4;
      for (o = [0, 0, 0, 0], r = e.slice(0), a = 0; 128 > a; a++) {
        for (n = 0 !== (t[Math.floor(a / 32)] & 1 << 31 - a % 32), n && (o = c(o, r)), s = 0 !== (1 & r[3]), i = 3; i > 0; i--) r[i] = r[i] >>> 1 | (1 & r[i - 1]) << 31;
        r[0] = r[0] >>> 1, s && (r[0] = r[0] ^ 225 << 24)
      }
      return o
    },
    _ghash: function (t, e, a) {
      var i, n, o = a.length;
      for (i = e.slice(0), n = 0; o > n; n += 4) i[0] ^= 4294967295 & a[n], i[1] ^= 4294967295 & a[n + 1], i[2] ^= 4294967295 & a[n + 2], i[3] ^= 4294967295 & a[n + 3], i = sjcl.mode.gcm._galoisMultiply(i, t);
      return i
    },
    _ctrMode: function (t, e, a, i, n, o) {
      {
        var r, s, u, c, l, h, f, m, d, p, g, k, y = sjcl.bitArray;
        y._xor4
      }
      for (d = a.length, p = y.bitLength(a), g = y.bitLength(i), k = y.bitLength(n), r = e.encrypt([0, 0, 0, 0]), 96 === k ? (s = n.slice(0), s = y.concat(s, [1])) : (s = sjcl.mode.gcm._ghash(r, [0, 0, 0, 0], n), s = sjcl.mode.gcm._ghash(r, s, [0, 0, Math.floor(k / 4294967296), 4294967295 & k])), u = sjcl.mode.gcm._ghash(r, [0, 0, 0, 0], i), h = s.slice(0), f = u.slice(0), t || (f = sjcl.mode.gcm._ghash(r, u, a)), l = 0; d > l; l += 4) h[3]++, c = e.encrypt(h), a[l] ^= c[0], a[l + 1] ^= c[1], a[l + 2] ^= c[2], a[l + 3] ^= c[3];
      return a = y.clamp(a, p), t && (f = sjcl.mode.gcm._ghash(r, u, a)), m = [Math.floor(g / 4294967296), 4294967295 & g, Math.floor(p / 4294967296), 4294967295 & p], f = sjcl.mode.gcm._ghash(r, f, m), c = e.encrypt(s), f[0] ^= c[0], f[1] ^= c[1], f[2] ^= c[2], f[3] ^= c[3], {
        tag: y.bitSlice(f, 0, o),
        data: a
      }
    }
  }, sjcl.misc.hmac = function (t, e) {
    this._hash = e = e || sjcl.hash.sha256;
    var a, i = [
        [],
        []
      ],
      n = e.prototype.blockSize / 32;
    for (this._baseHash = [new e, new e], t.length > n && (t = e.hash(t)), a = 0; n > a; a++) t[a] || (t[a] = 0), i[0][a] = 909522486 ^ t[a], i[1][a] = 1549556828 ^ t[a];
    this._baseHash[0].update(i[0]), this._baseHash[1].update(i[1])
  }, sjcl.misc.hmac.prototype.encrypt = sjcl.misc.hmac.prototype.mac = function (t) {
    var e = new this._hash(this._baseHash[0]).update(t).finalize();
    return new this._hash(this._baseHash[1]).update(e).finalize()
  }, sjcl.misc.pbkdf2 = function (t, e, a, i, n, o) {
    if (a = a || 1e3, o = o || sjcl.hash.sha256, 0 > i || 0 > a) throw sjcl.exception.invalid("invalid params to pbkdf2");
    "string" == typeof t && (t = sjcl.codec.utf8String.toBits(t)), n = n || sjcl.misc.hmac;
    var r, s, u, c, l, h = new n(t, o),
      f = [],
      m = sjcl.bitArray;
    for (l = 1; 32 * f.length < (i || 1); l++) try {
      for (r = s = h.encrypt(m.concat(e, [l])), u = 1; a > u; u++)
        for (s = h.encrypt(s), c = 0; c < s.length; c++) r[c] ^= s[c]
    } finally {
      f = f.concat(r)
    }
    return i && (f = m.clamp(f, i)), f
  }, sjcl.prng = function (t) {
    this._pools = [new sjcl.hash.sha256], this._poolEntropy = [0], this._reseedCount = 0, this._robins = {}, this._eventId = 0, this._collectorIds = {}, this._collectorIdNext = 0, this._strength = 0, this._poolStrength = 0, this._nextReseed = 0, this._key = [0, 0, 0, 0, 0, 0, 0, 0], this._counter = [0, 0, 0, 0], this._cipher = void 0, this._defaultParanoia = t, this._collectorsStarted = !1, this._callbacks = {
      progress: {},
      seeded: {}
    }, this._callbackI = 0, this._NOT_READY = 0, this._READY = 1, this._REQUIRES_RESEED = 2, this._MAX_WORDS_PER_BURST = 65536, this._PARANOIA_LEVELS = [0, 48, 64, 96, 128, 192, 256, 384, 512, 768, 1024], this._MILLISECONDS_PER_RESEED = 3e4, this._BITS_PER_RESEED = 80
  }, sjcl.prng.prototype = {
    randomWords: function (t, e) {
      var a, i, n = [],
        o = this.isReady(e);
      if (o === this._NOT_READY) throw new sjcl.exception.notReady("generator isn't seeded");
      for (o & this._REQUIRES_RESEED && this._reseedFromPools(!(o & this._READY)), a = 0; t > a; a += 4)(a + 1) % this._MAX_WORDS_PER_BURST === 0 && this._gate(), i = this._gen4words(), n.push(i[0], i[1], i[2], i[3]);
      return this._gate(), n.slice(0, t)
    },
    setDefaultParanoia: function (t) {
      this._defaultParanoia = t
    },
    addEntropy: function (t, e, a) {
      a = a || "user";
      var i, n, o, r = (new Date).valueOf(),
        s = this._robins[a],
        u = this.isReady(),
        c = 0;
      switch (i = this._collectorIds[a], void 0 === i && (i = this._collectorIds[a] = this._collectorIdNext++), void 0 === s && (s = this._robins[a] = 0), this._robins[a] = (this._robins[a] + 1) % this._pools.length, typeof t) {
        case "number":
          void 0 === e && (e = 1), this._pools[s].update([i, this._eventId++, 1, e, r, 1, 0 | t]);
          break;
        case "object":
          var l = Object.prototype.toString.call(t);
          if ("[object Uint32Array]" === l) {
            for (o = [], n = 0; n < t.length; n++) o.push(t[n]);
            t = o
          } else
            for ("[object Array]" !== l && (c = 1), n = 0; n < t.length && !c; n++) "number" != typeof t[n] && (c = 1);
          if (!c) {
            if (void 0 === e)
              for (e = 0, n = 0; n < t.length; n++)
                for (o = t[n]; o > 0;) e++, o >>>= 1;
            this._pools[s].update([i, this._eventId++, 2, e, r, t.length].concat(t))
          }
          break;
        case "string":
          void 0 === e && (e = t.length), this._pools[s].update([i, this._eventId++, 3, e, r, t.length]), this._pools[s].update(t);
          break;
        default:
          c = 1
      }
      if (c) throw new sjcl.exception.bug("random: addEntropy only supports number, array of numbers or string");
      this._poolEntropy[s] += e, this._poolStrength += e, u === this._NOT_READY && (this.isReady() !== this._NOT_READY && this._fireEvent("seeded", Math.max(this._strength, this._poolStrength)), this._fireEvent("progress", this.getProgress()))
    },
    isReady: function (t) {
      var e = this._PARANOIA_LEVELS[void 0 !== t ? t : this._defaultParanoia];
      return this._strength && this._strength >= e ? this._poolEntropy[0] > this._BITS_PER_RESEED && (new Date).valueOf() > this._nextReseed ? this._REQUIRES_RESEED | this._READY : this._READY : this._poolStrength >= e ? this._REQUIRES_RESEED | this._NOT_READY : this._NOT_READY
    },
    getProgress: function (t) {
      var e = this._PARANOIA_LEVELS[t ? t : this._defaultParanoia];
      return this._strength >= e ? 1 : this._poolStrength > e ? 1 : this._poolStrength / e
    },
    startCollectors: function () {
      if (!this._collectorsStarted) {
        if (window.addEventListener) window.addEventListener("load", this._loadTimeCollector, !1), window.addEventListener("mousemove", this._mouseCollector, !1);
        else {
          if (!document.attachEvent) throw new sjcl.exception.bug("can't attach event");
          document.attachEvent("onload", this._loadTimeCollector), document.attachEvent("onmousemove", this._mouseCollector)
        }
        this._collectorsStarted = !0
      }
    },
    stopCollectors: function () {
      this._collectorsStarted && (window.removeEventListener ? (window.removeEventListener("load", this._loadTimeCollector, !1), window.removeEventListener("mousemove", this._mouseCollector, !1)) : window.detachEvent && (window.detachEvent("onload", this._loadTimeCollector), window.detachEvent("onmousemove", this._mouseCollector)), this._collectorsStarted = !1)
    },
    addEventListener: function (t, e) {
      this._callbacks[t][this._callbackI++] = e
    },
    removeEventListener: function (t, e) {
      var a, i, n = this._callbacks[t],
        o = [];
      for (i in n) n.hasOwnProperty(i) && n[i] === e && o.push(i);
      for (a = 0; a < o.length; a++) i = o[a], delete n[i]
    },
    _gen4words: function () {
      for (var t = 0; 4 > t && (this._counter[t] = this._counter[t] + 1 | 0, !this._counter[t]); t++);
      return this._cipher.encrypt(this._counter)
    },
    _gate: function () {
      this._key = this._gen4words().concat(this._gen4words()), this._cipher = new sjcl.cipher.aes(this._key)
    },
    _reseed: function (t) {
      this._key = sjcl.hash.sha256.hash(this._key.concat(t)), this._cipher = new sjcl.cipher.aes(this._key);
      for (var e = 0; 4 > e && (this._counter[e] = this._counter[e] + 1 | 0, !this._counter[e]); e++);
    },
    _reseedFromPools: function (t) {
      var e, a = [],
        i = 0;
      for (this._nextReseed = a[0] = (new Date).valueOf() + this._MILLISECONDS_PER_RESEED, e = 0; 16 > e; e++) a.push(4294967296 * Math.random() | 0);
      for (e = 0; e < this._pools.length && (a = a.concat(this._pools[e].finalize()), i += this._poolEntropy[e], this._poolEntropy[e] = 0, t || !(this._reseedCount & 1 << e)); e++);
      this._reseedCount >= 1 << this._pools.length && (this._pools.push(new sjcl.hash.sha256), this._poolEntropy.push(0)), this._poolStrength -= i, i > this._strength && (this._strength = i), this._reseedCount++, this._reseed(a)
    },
    _mouseCollector: function (t) {
      var e = t.x || t.clientX || t.offsetX || 0,
        a = t.y || t.clientY || t.offsetY || 0;
      sjcl.random.addEntropy([e, a], 2, "mouse")
    },
    _loadTimeCollector: function (t) {
      sjcl.random.addEntropy((new Date).valueOf(), 2, "loadtime")
    },
    _fireEvent: function (t, e) {
      var a, i = sjcl.random._callbacks[t],
        n = [];
      for (a in i) i.hasOwnProperty(a) && n.push(i[a]);
      for (a = 0; a < n.length; a++) n[a](e)
    }
  }, sjcl.random = new sjcl.prng(6),
  function () {
    try {
      var t = new Uint32Array(32);
      crypto.getRandomValues(t), sjcl.random.addEntropy(t, 1024, "crypto.getRandomValues")
    } catch (e) {}
  }(), sjcl.json = {
    defaults: {
      v: 1,
      iter: 1e3,
      ks: 128,
      ts: 64,
      mode: "ccm",
      adata: "",
      cipher: "aes"
    },
    encrypt: function (t, e, a, i) {
      a = a || {}, i = i || {};
      var n, o, r, s = sjcl.json,
        u = s._add({
          iv: sjcl.random.randomWords(4, 0)
        }, s.defaults);
      if (s._add(u, a), r = u.adata, "string" == typeof u.salt && (u.salt = sjcl.codec.base64.toBits(u.salt)), "string" == typeof u.iv && (u.iv = sjcl.codec.base64.toBits(u.iv)), !sjcl.mode[u.mode] || !sjcl.cipher[u.cipher] || "string" == typeof t && u.iter <= 100 || 64 !== u.ts && 96 !== u.ts && 128 !== u.ts || 128 !== u.ks && 192 !== u.ks && 256 !== u.ks || u.iv.length < 2 || u.iv.length > 4) throw new sjcl.exception.invalid("json encrypt: invalid parameters");
      return "string" == typeof t ? a.compat && "veness" == a.compat ? t = sjcl.misc.venessCompatKDF(t, u) : (n = sjcl.misc.cachedPbkdf2(t, u), t = n.key.slice(0, u.ks / 32), u.salt = n.salt) : sjcl.ecc && t instanceof sjcl.ecc.elGamal.publicKey && (n = t.kem(), u.kemtag = n.tag, t = n.key.slice(0, u.ks / 32)), "string" == typeof e && (e = sjcl.codec.utf8String.toBits(e)), "string" == typeof r && (r = sjcl.codec.utf8String.toBits(r)), o = new sjcl.cipher[u.cipher](t), s._add(i, u), i.key = t, u.ct = sjcl.mode[u.mode].encrypt(o, e, u.iv, r, u.ts), s.encode(u)
    },
    decrypt: function (t, e, a, i) {
      a = a || {}, i = i || {};
      var n, o, r, s = sjcl.json,
        u = s._add(s._add(s._add({}, s.defaults), s.decode(e)), a, !0),
        c = u.adata;
      if ("string" == typeof u.salt && (u.salt = sjcl.codec.base64.toBits(u.salt)), "string" == typeof u.iv && (u.iv = sjcl.codec.base64.toBits(u.iv)), !sjcl.mode[u.mode] || !sjcl.cipher[u.cipher] || "string" == typeof t && u.iter <= 100 || 64 !== u.ts && 96 !== u.ts && 128 !== u.ts || 128 !== u.ks && 192 !== u.ks && 256 !== u.ks || !u.iv || u.iv.length < 2 || u.iv.length > 4) throw new sjcl.exception.invalid("json decrypt: invalid parameters");
      return "string" == typeof t ? a.compat && "veness" == a.compat ? t = sjcl.misc.venessCompatKDF(t, u) : (o = sjcl.misc.cachedPbkdf2(t, u), t = o.key.slice(0, u.ks / 32), u.salt = o.salt) : sjcl.ecc && t instanceof sjcl.ecc.elGamal.secretKey && (t = t.unkem(sjcl.codec.base64.toBits(u.kemtag)).slice(0, u.ks / 32)), "string" == typeof c && (c = sjcl.codec.utf8String.toBits(c)), r = new sjcl.cipher[u.cipher](t), n = sjcl.mode[u.mode].decrypt(r, u.ct, u.iv, c, u.ts), s._add(i, u), i.key = t, sjcl.codec.utf8String.fromBits(n)
    },
    encode: function (t) {
      var e, a = "{",
        i = "";
      for (e in t)
        if (t.hasOwnProperty(e)) {
          if (!e.match(/^[a-z0-9]+$/i)) throw new sjcl.exception.invalid("json encode: invalid property name");
          switch (a += i + '"' + e + '":', i = ",", typeof t[e]) {
            case "number":
            case "boolean":
              a += t[e];
              break;
            case "string":
              a += '"' + escape(t[e]) + '"';
              break;
            case "object":
              a += '"' + sjcl.codec.base64.fromBits(t[e], 0) + '"';
              break;
            default:
              throw new sjcl.exception.bug("json encode: unsupported type")
          }
        }
      return a + "}"
    },
    decode: function (t) {
      if (t = t.replace(/\s/g, ""), !t.match(/^\{.*\}$/)) throw new sjcl.exception.invalid("json decode: this isn't json!");
      var e, a, i = t.replace(/^\{|\}$/g, "").split(/,/),
        n = {};
      for (e = 0; e < i.length; e++) {
        if (!(a = i[e].match(/^(?:(["']?)([a-z][a-z0-9]*)\1):(?:(\d+)|"([a-z0-9+\/%*_.@=\-]*)")$/i))) throw new sjcl.exception.invalid("json decode: this isn't json!");
        a[3] ? n[a[2]] = parseInt(a[3], 10) : n[a[2]] = a[2].match(/^(ct|salt|iv)$/) ? sjcl.codec.base64.toBits(a[4]) : unescape(a[4]);
      }
      return n
    },
    _add: function (t, e, a) {
      if (void 0 === t && (t = {}), void 0 === e) return t;
      var i;
      for (i in e)
        if (e.hasOwnProperty(i)) {
          if (a && void 0 !== t[i] && t[i] !== e[i]) throw new sjcl.exception.invalid("required parameter overridden");
          t[i] = e[i]
        }
      return t
    },
    _subtract: function (t, e) {
      var a, i = {};
      for (a in t) t.hasOwnProperty(a) && t[a] !== e[a] && (i[a] = t[a]);
      return i
    },
    _filter: function (t, e) {
      var a, i = {};
      for (a = 0; a < e.length; a++) void 0 !== t[e[a]] && (i[e[a]] = t[e[a]]);
      return i
    }
  }, sjcl.encrypt = sjcl.json.encrypt, sjcl.decrypt = sjcl.json.decrypt, sjcl.misc._pbkdf2Cache = {}, sjcl.misc.cachedPbkdf2 = function (t, e) {
    var a, i, n, o, r = sjcl.misc._pbkdf2Cache;
    return e = e || {}, o = e.iter || 1e3, i = r[t] = r[t] || {}, a = i[o] = i[o] || {
      firstSalt: e.salt && e.salt.length ? e.salt.slice(0) : sjcl.random.randomWords(2, 0)
    }, n = void 0 === e.salt ? a.firstSalt : e.salt, a[n] = a[n] || sjcl.misc.pbkdf2(t, n, e.iter), {
      key: a[n].slice(0),
      salt: n.slice(0)
    }
  }, sjcl.misc.venessCompatKDF = function (t, e) {
    var a, i = sjcl.bitArray;
    if ("ctr" != e.mode || "aes" != e.cipher) throw new sjcl.exception.invalid("veness compat: only for aes in ctr mode");
    return t = i.concat(sjcl.codec.utf8String.toBits(t), [0, 0, 0, 0, 0, 0, 0, 0]).slice(0, 8), a = new sjcl.cipher[e.cipher](t), t = i.clamp(t, 128), t = a.encrypt(t), t.concat(t)
  }, sjcl.bn = function (t) {
    this.initWith(t)
  }, sjcl.bn.prototype = {
    radix: 24,
    maxMul: 8,
    _class: sjcl.bn,
    copy: function () {
      return new this._class(this)
    },
    initWith: function (t) {
      var e, a = 0;
      switch (typeof t) {
        case "object":
          this.limbs = t.limbs.slice(0);
          break;
        case "number":
          this.limbs = [t], this.normalize();
          break;
        case "string":
          for (t = t.replace(/^0x/, ""), this.limbs = [], e = this.radix / 4, a = 0; a < t.length; a += e) this.limbs.push(parseInt(t.substring(Math.max(t.length - a - e, 0), t.length - a), 16));
          break;
        default:
          this.limbs = [0]
      }
      return this
    },
    equals: function (t) {
      "number" == typeof t && (t = new this._class(t));
      var e, a = 0;
      for (this.fullReduce(), t.fullReduce(), e = 0; e < this.limbs.length || e < t.limbs.length; e++) a |= this.getLimb(e) ^ t.getLimb(e);
      return 0 === a
    },
    getLimb: function (t) {
      return t >= this.limbs.length ? 0 : this.limbs[t]
    },
    greaterEquals: function (t) {
      "number" == typeof t && (t = new this._class(t));
      var e, a, i, n = 0,
        o = 0;
      for (e = Math.max(this.limbs.length, t.limbs.length) - 1; e >= 0; e--) a = this.getLimb(e), i = t.getLimb(e), o |= i - a & ~n, n |= a - i & ~o;
      return (o | ~n) >>> 31
    },
    toString: function () {
      this.fullReduce();
      var t, e, a = "",
        i = this.limbs;
      for (t = 0; t < this.limbs.length; t++) {
        for (e = i[t].toString(16); t < this.limbs.length - 1 && e.length < 6;) e = "0" + e;
        a = e + a
      }
      return "0x" + a
    },
    addM: function (t) {
      "object" != typeof t && (t = new this._class(t));
      var e, a = this.limbs,
        i = t.limbs;
      for (e = a.length; e < i.length; e++) a[e] = 0;
      for (e = 0; e < i.length; e++) a[e] += i[e];
      return this
    },
    doubleM: function () {
      var t, e, a = 0,
        i = this.radix,
        n = this.radixMask,
        o = this.limbs;
      for (t = 0; t < o.length; t++) e = o[t], e = e + e + a, o[t] = e & n, a = e >> i;
      return a && o.push(a), this
    },
    halveM: function () {
      var t, e, a = 0,
        i = this.radix,
        n = this.limbs;
      for (t = n.length - 1; t >= 0; t--) e = n[t], n[t] = e + a >> 1, a = (1 & e) << i;
      return n[n.length - 1] || n.pop(), this
    },
    subM: function (t) {
      "object" != typeof t && (t = new this._class(t));
      var e, a = this.limbs,
        i = t.limbs;
      for (e = a.length; e < i.length; e++) a[e] = 0;
      for (e = 0; e < i.length; e++) a[e] -= i[e];
      return this
    },
    mod: function (t) {
      var e = !this.greaterEquals(new sjcl.bn(0));
      t = new sjcl.bn(t).normalize();
      var a = new sjcl.bn(this).normalize(),
        i = 0;
      for (e && (a = new sjcl.bn(0).subM(a).normalize()); a.greaterEquals(t); i++) t.doubleM();
      for (e && (a = t.sub(a).normalize()); i > 0; i--) t.halveM(), a.greaterEquals(t) && a.subM(t).normalize();
      return a.trim()
    },
    inverseMod: function (t) {
      var e, a, i = new sjcl.bn(1),
        n = new sjcl.bn(0),
        o = new sjcl.bn(this),
        r = new sjcl.bn(t),
        s = 1;
      if (!(1 & t.limbs[0])) throw new sjcl.exception.invalid("inverseMod: p must be odd");
      do
        for (1 & o.limbs[0] && (o.greaterEquals(r) || (e = o, o = r, r = e, e = i, i = n, n = e), o.subM(r), o.normalize(), i.greaterEquals(n) || i.addM(t), i.subM(n)), o.halveM(), 1 & i.limbs[0] && i.addM(t), i.normalize(), i.halveM(), a = s = 0; a < o.limbs.length; a++) s |= o.limbs[a]; while (s);
      if (!r.equals(1)) throw new sjcl.exception.invalid("inverseMod: p and x must be relatively prime");
      return n
    },
    add: function (t) {
      return this.copy().addM(t)
    },
    sub: function (t) {
      return this.copy().subM(t)
    },
    mul: function (t) {
      "number" == typeof t && (t = new this._class(t));
      var e, a, i, n = this.limbs,
        o = t.limbs,
        r = n.length,
        s = o.length,
        u = new this._class,
        c = u.limbs,
        l = this.maxMul;
      for (e = 0; e < this.limbs.length + t.limbs.length + 1; e++) c[e] = 0;
      for (e = 0; r > e; e++) {
        for (i = n[e], a = 0; s > a; a++) c[e + a] += i * o[a];
        --l || (l = this.maxMul, u.cnormalize())
      }
      return u.cnormalize().reduce()
    },
    square: function () {
      return this.mul(this)
    },
    power: function (t) {
      "number" == typeof t ? t = [t] : void 0 !== t.limbs && (t = t.normalize().limbs);
      var e, a, i = new this._class(1),
        n = this;
      for (e = 0; e < t.length; e++)
        for (a = 0; a < this.radix; a++) t[e] & 1 << a && (i = i.mul(n)), n = n.square();
      return i
    },
    mulmod: function (t, e) {
      return this.mod(e).mul(t.mod(e)).mod(e)
    },
    powermod: function (t, e) {
      for (var a = new sjcl.bn(1), i = new sjcl.bn(this), n = new sjcl.bn(t);;) {
        if (1 & n.limbs[0] && (a = a.mulmod(i, e)), n.halveM(), n.equals(0)) break;
        i = i.mulmod(i, e)
      }
      return a.normalize().reduce()
    },
    trim: function () {
      var t, e = this.limbs;
      do t = e.pop(); while (e.length && 0 === t);
      return e.push(t), this
    },
    reduce: function () {
      return this
    },
    fullReduce: function () {
      return this.normalize()
    },
    normalize: function () {
      var t, e, a, i = 0,
        n = (this.placeVal, this.ipv),
        o = this.limbs,
        r = o.length,
        s = this.radixMask;
      for (t = 0; r > t || 0 !== i && -1 !== i; t++) e = (o[t] || 0) + i, a = o[t] = e & s, i = (e - a) * n;
      return -1 === i && (o[t - 1] -= this.placeVal), this
    },
    cnormalize: function () {
      var t, e, a, i = 0,
        n = this.ipv,
        o = this.limbs,
        r = o.length,
        s = this.radixMask;
      for (t = 0; r - 1 > t; t++) e = o[t] + i, a = o[t] = e & s, i = (e - a) * n;
      return o[t] += i, this
    },
    toBits: function (t) {
      this.fullReduce(), t = t || this.exponent || this.bitLength();
      var e = Math.floor((t - 1) / 24),
        a = sjcl.bitArray,
        i = (t + 7 & -8) % this.radix || this.radix,
        n = [a.partial(i, this.getLimb(e))];
      for (e--; e >= 0; e--) n = a.concat(n, [a.partial(Math.min(this.radix, t), this.getLimb(e))]), t -= this.radix;
      return n
    },
    bitLength: function () {
      this.fullReduce();
      for (var t = this.radix * (this.limbs.length - 1), e = this.limbs[this.limbs.length - 1]; e; e >>>= 1) t++;
      return t + 7 & -8
    }
  }, sjcl.bn.fromBits = function (t) {
    var e = this,
      a = new e,
      i = [],
      n = sjcl.bitArray,
      o = this.prototype,
      r = Math.min(this.bitLength || 4294967296, n.bitLength(t)),
      s = r % o.radix || o.radix;
    for (i[0] = n.extract(t, 0, s); r > s; s += o.radix) i.unshift(n.extract(t, s, o.radix));
    return a.limbs = i, a
  }, sjcl.bn.prototype.ipv = 1 / (sjcl.bn.prototype.placeVal = Math.pow(2, sjcl.bn.prototype.radix)), sjcl.bn.prototype.radixMask = (1 << sjcl.bn.prototype.radix) - 1, sjcl.bn.pseudoMersennePrime = function (t, e) {
    function a(t) {
      this.initWith(t)
    }
    var i, n, o, r = a.prototype = new sjcl.bn;
    for (o = r.modOffset = Math.ceil(n = t / r.radix), r.exponent = t, r.offset = [], r.factor = [], r.minOffset = o, r.fullMask = 0, r.fullOffset = [], r.fullFactor = [], r.modulus = a.modulus = new sjcl.bn(Math.pow(2, t)), r.fullMask = 0 | -Math.pow(2, t % r.radix), i = 0; i < e.length; i++) r.offset[i] = Math.floor(e[i][0] / r.radix - n), r.fullOffset[i] = Math.ceil(e[i][0] / r.radix - n), r.factor[i] = e[i][1] * Math.pow(.5, t - e[i][0] + r.offset[i] * r.radix), r.fullFactor[i] = e[i][1] * Math.pow(.5, t - e[i][0] + r.fullOffset[i] * r.radix), r.modulus.addM(new sjcl.bn(Math.pow(2, e[i][0]) * e[i][1])), r.minOffset = Math.min(r.minOffset, -r.offset[i]);
    return r._class = a, r.modulus.cnormalize(), r.reduce = function () {
      var t, e, a, i, n = this.modOffset,
        o = this.limbs,
        r = this.offset,
        s = this.offset.length,
        u = this.factor;
      for (t = this.minOffset; o.length > n;) {
        for (a = o.pop(), i = o.length, e = 0; s > e; e++) o[i + r[e]] -= u[e] * a;
        t--, t || (o.push(0), this.cnormalize(), t = this.minOffset)
      }
      return this.cnormalize(), this
    }, r._strongReduce = -1 === r.fullMask ? r.reduce : function () {
      var t, e, a = this.limbs,
        i = a.length - 1;
      if (this.reduce(), i === this.modOffset - 1) {
        for (e = a[i] & this.fullMask, a[i] -= e, t = 0; t < this.fullOffset.length; t++) a[i + this.fullOffset[t]] -= this.fullFactor[t] * e;
        this.normalize()
      }
    }, r.fullReduce = function () {
      var t, e;
      for (this._strongReduce(), this.addM(this.modulus), this.addM(this.modulus), this.normalize(), this._strongReduce(), e = this.limbs.length; e < this.modOffset; e++) this.limbs[e] = 0;
      for (t = this.greaterEquals(this.modulus), e = 0; e < this.limbs.length; e++) this.limbs[e] -= this.modulus.limbs[e] * t;
      return this.cnormalize(), this
    }, r.inverse = function () {
      return this.power(this.modulus.sub(2))
    }, a.fromBits = sjcl.bn.fromBits, a
  }, sjcl.bn.prime = {
    p127: sjcl.bn.pseudoMersennePrime(127, [
      [0, -1]
    ]),
    p25519: sjcl.bn.pseudoMersennePrime(255, [
      [0, -19]
    ]),
    p192: sjcl.bn.pseudoMersennePrime(192, [
      [0, -1],
      [64, -1]
    ]),
    p224: sjcl.bn.pseudoMersennePrime(224, [
      [0, 1],
      [96, -1]
    ]),
    p256: sjcl.bn.pseudoMersennePrime(256, [
      [0, -1],
      [96, 1],
      [192, 1],
      [224, -1]
    ]),
    p384: sjcl.bn.pseudoMersennePrime(384, [
      [0, -1],
      [32, 1],
      [96, -1],
      [128, -1]
    ]),
    p521: sjcl.bn.pseudoMersennePrime(521, [
      [0, -1]
    ])
  }, sjcl.bn.random = function (t, e) {
    "object" != typeof t && (t = new sjcl.bn(t));
    for (var a, i, n = t.limbs.length, o = t.limbs[n - 1] + 1, r = new sjcl.bn;;) {
      do a = sjcl.random.randomWords(n, e), a[n - 1] < 0 && (a[n - 1] += 4294967296); while (Math.floor(a[n - 1] / o) === Math.floor(4294967296 / o));
      for (a[n - 1] %= o, i = 0; n - 1 > i; i++) a[i] &= t.radixMask;
      if (r.limbs = a, !r.greaterEquals(t)) return r
    }
  }, sjcl.ecc = {}, sjcl.ecc.point = function (t, e, a) {
    void 0 === e ? this.isIdentity = !0 : (this.x = e, this.y = a, this.isIdentity = !1), this.curve = t
  }, sjcl.ecc.point.prototype = {
    toJac: function () {
      return new sjcl.ecc.pointJac(this.curve, this.x, this.y, new this.curve.field(1))
    },
    mult: function (t) {
      return this.toJac().mult(t, this).toAffine()
    },
    mult2: function (t, e, a) {
      return this.toJac().mult2(t, this, e, a).toAffine()
    },
    multiples: function () {
      var t, e, a;
      if (void 0 === this._multiples)
        for (a = this.toJac().doubl(), t = this._multiples = [new sjcl.ecc.point(this.curve), this, a.toAffine()], e = 3; 16 > e; e++) a = a.add(this), t.push(a.toAffine());
      return this._multiples
    },
    isValid: function () {
      return this.y.square().equals(this.curve.b.add(this.x.mul(this.curve.a.add(this.x.square()))))
    },
    toBits: function () {
      return sjcl.bitArray.concat(this.x.toBits(), this.y.toBits())
    }
  }, sjcl.ecc.pointJac = function (t, e, a, i) {
    void 0 === e ? this.isIdentity = !0 : (this.x = e, this.y = a, this.z = i, this.isIdentity = !1), this.curve = t
  }, sjcl.ecc.pointJac.prototype = {
    add: function (t) {
      var e, a, i, n, o, r, s, u, c, l, h, f = this;
      if (f.curve !== t.curve) throw "sjcl.ecc.add(): Points must be on the same curve to add them!";
      return f.isIdentity ? t.toJac() : t.isIdentity ? f : (e = f.z.square(), a = t.x.mul(e).subM(f.x), a.equals(0) ? f.y.equals(t.y.mul(e.mul(f.z))) ? f.doubl() : new sjcl.ecc.pointJac(f.curve) : (i = t.y.mul(e.mul(f.z)).subM(f.y), n = a.square(), o = i.square(), r = a.square().mul(a).addM(f.x.add(f.x).mul(n)), s = o.subM(r), u = f.x.mul(n).subM(s).mul(i), c = f.y.mul(a.square().mul(a)), l = u.subM(c), h = f.z.mul(a), new sjcl.ecc.pointJac(this.curve, s, l, h)))
    },
    doubl: function () {
      if (this.isIdentity) return this;
      var t = this.y.square(),
        e = t.mul(this.x.mul(4)),
        a = t.square().mul(8),
        i = this.z.square(),
        n = this.x.sub(i).mul(3).mul(this.x.add(i)),
        o = n.square().subM(e).subM(e),
        r = e.sub(o).mul(n).subM(a),
        s = this.y.add(this.y).mul(this.z);
      return new sjcl.ecc.pointJac(this.curve, o, r, s)
    },
    toAffine: function () {
      if (this.isIdentity || this.z.equals(0)) return new sjcl.ecc.point(this.curve);
      var t = this.z.inverse(),
        e = t.square();
      return new sjcl.ecc.point(this.curve, this.x.mul(e).fullReduce(), this.y.mul(e.mul(t)).fullReduce())
    },
    mult: function (t, e) {
      "number" == typeof t ? t = [t] : void 0 !== t.limbs && (t = t.normalize().limbs);
      var a, i, n = new sjcl.ecc.point(this.curve).toJac(),
        o = e.multiples();
      for (a = t.length - 1; a >= 0; a--)
        for (i = sjcl.bn.prototype.radix - 4; i >= 0; i -= 4) n = n.doubl().doubl().doubl().doubl().add(o[t[a] >> i & 15]);
      return n
    },
    mult2: function (t, e, a, i) {
      "number" == typeof t ? t = [t] : void 0 !== t.limbs && (t = t.normalize().limbs), "number" == typeof a ? a = [a] : void 0 !== a.limbs && (a = a.normalize().limbs);
      var n, o, r, s, u = new sjcl.ecc.point(this.curve).toJac(),
        c = e.multiples(),
        l = i.multiples();
      for (n = Math.max(t.length, a.length) - 1; n >= 0; n--)
        for (r = 0 | t[n], s = 0 | a[n], o = sjcl.bn.prototype.radix - 4; o >= 0; o -= 4) u = u.doubl().doubl().doubl().doubl().add(c[r >> o & 15]).add(l[s >> o & 15]);
      return u
    },
    isValid: function () {
      var t = this.z.square(),
        e = t.square(),
        a = e.mul(t);
      return this.y.square().equals(this.curve.b.mul(a).add(this.x.mul(this.curve.a.mul(e).add(this.x.square()))))
    }
  }, sjcl.ecc.curve = function (t, e, a, i, n, o) {
    this.field = t, this.r = t.prototype.modulus.sub(e), this.a = new t(a), this.b = new t(i), this.G = new sjcl.ecc.point(this, new t(n), new t(o))
  }, sjcl.ecc.curve.prototype.fromBits = function (t) {
    var e = sjcl.bitArray,
      a = this.field.prototype.exponent + 7 & -8,
      i = new sjcl.ecc.point(this, this.field.fromBits(e.bitSlice(t, 0, a)), this.field.fromBits(e.bitSlice(t, a, 2 * a)));
    if (!i.isValid()) throw new sjcl.exception.corrupt("not on the curve!");
    return i
  }, sjcl.ecc.curves = {
    c192: new sjcl.ecc.curve(sjcl.bn.prime.p192, "0x662107c8eb94364e4b2dd7ce", -3, "0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1", "0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012", "0x07192b95ffc8da78631011ed6b24cdd573f977a11e794811"),
    c224: new sjcl.ecc.curve(sjcl.bn.prime.p224, "0xe95c1f470fc1ec22d6baa3a3d5c4", -3, "0xb4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4", "0xb70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21", "0xbd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34"),
    c256: new sjcl.ecc.curve(sjcl.bn.prime.p256, "0x4319055358e8617b0c46353d039cdaae", -3, "0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", "0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", "0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"),
    c384: new sjcl.ecc.curve(sjcl.bn.prime.p384, "0x389cb27e0bc8d21fa7e5f24cb74f58851313e696333ad68c", -3, "0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef", "0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7", "0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f")
  }, sjcl.ecc._dh = function (t) {
    sjcl.ecc[t] = {
      publicKey: function (t, e) {
        this._curve = t, this._curveBitLength = t.r.bitLength(), e instanceof Array ? this._point = t.fromBits(e) : this._point = e, this.get = function () {
          var t = this._point.toBits(),
            e = sjcl.bitArray.bitLength(t),
            a = sjcl.bitArray.bitSlice(t, 0, e / 2),
            i = sjcl.bitArray.bitSlice(t, e / 2);
          return {
            x: a,
            y: i
          }
        }
      },
      secretKey: function (t, e) {
        this._curve = t, this._curveBitLength = t.r.bitLength(), this._exponent = e, this.get = function () {
          return this._exponent.toBits()
        }
      },
      generateKeys: function (e, a, i) {
        if (void 0 === e && (e = 256), "number" == typeof e && (e = sjcl.ecc.curves["c" + e], void 0 === e)) throw new sjcl.exception.invalid("no such curve");
        void 0 === i && (i = sjcl.bn.random(e.r, a));
        var n = e.G.mult(i);
        return {
          pub: new sjcl.ecc[t].publicKey(e, n),
          sec: new sjcl.ecc[t].secretKey(e, i)
        }
      }
    }
  }, sjcl.ecc._dh("elGamal"), sjcl.ecc.elGamal.publicKey.prototype = {
    kem: function (t) {
      var e = sjcl.bn.random(this._curve.r, t),
        a = this._curve.G.mult(e).toBits(),
        i = sjcl.hash.sha256.hash(this._point.mult(e).toBits());
      return {
        key: i,
        tag: a
      }
    }
  }, sjcl.ecc.elGamal.secretKey.prototype = {
    unkem: function (t) {
      return sjcl.hash.sha256.hash(this._curve.fromBits(t).mult(this._exponent).toBits())
    },
    dh: function (t) {
      return sjcl.hash.sha256.hash(t._point.mult(this._exponent).toBits())
    }
  }, sjcl.ecc._dh("ecdsa"), sjcl.ecc.ecdsa.secretKey.prototype = {
    sign: function (t, e, a, i) {
      sjcl.bitArray.bitLength(t) > this._curveBitLength && (t = sjcl.bitArray.clamp(t, this._curveBitLength));
      var n = this._curve.r,
        o = n.bitLength(),
        r = i || sjcl.bn.random(n.sub(1), e).add(1),
        s = this._curve.G.mult(r).x.mod(n),
        u = sjcl.bn.fromBits(t).add(s.mul(this._exponent)),
        c = a ? u.inverseMod(n).mul(r).mod(n) : u.mul(r.inverseMod(n)).mod(n);
      return sjcl.bitArray.concat(s.toBits(o), c.toBits(o))
    }
  }, sjcl.ecc.ecdsa.publicKey.prototype = {
    verify: function (t, e, a) {
      sjcl.bitArray.bitLength(t) > this._curveBitLength && (t = sjcl.bitArray.clamp(t, this._curveBitLength));
      var i = sjcl.bitArray,
        n = this._curve.r,
        o = this._curveBitLength,
        r = sjcl.bn.fromBits(i.bitSlice(e, 0, o)),
        s = sjcl.bn.fromBits(i.bitSlice(e, o, 2 * o)),
        u = a ? s : s.inverseMod(n),
        c = sjcl.bn.fromBits(t).mul(u).mod(n),
        l = r.mul(u).mod(n),
        h = this._curve.G.mult2(c, l, this._point).x;
      if (r.equals(0) || s.equals(0) || r.greaterEquals(n) || s.greaterEquals(n) || !h.equals(r)) {
        if (void 0 === a) return this.verify(t, e, !0);
        throw new sjcl.exception.corrupt("signature didn't check out")
      }
      return !0
    }
  }, sjcl.keyexchange.srp = {
    makeVerifier: function (t, e, a, i) {
      var n;
      return n = sjcl.keyexchange.srp.makeX(t, e, a), n = sjcl.bn.fromBits(n), i.g.powermod(n, i.N)
    },
    makeX: function (t, e, a) {
      var i = sjcl.hash.sha1.hash(t + ":" + e);
      return sjcl.hash.sha1.hash(sjcl.bitArray.concat(a, i))
    },
    knownGroup: function (t) {
      return "string" != typeof t && (t = t.toString()), sjcl.keyexchange.srp._didInitKnownGroups || sjcl.keyexchange.srp._initKnownGroups(), sjcl.keyexchange.srp._knownGroups[t]
    },
    _didInitKnownGroups: !1,
    _initKnownGroups: function () {
      var t, e, a;
      for (t = 0; t < sjcl.keyexchange.srp._knownGroupSizes.length; t++) e = sjcl.keyexchange.srp._knownGroupSizes[t].toString(), a = sjcl.keyexchange.srp._knownGroups[e], a.N = new sjcl.bn(a.N), a.g = new sjcl.bn(a.g);
      sjcl.keyexchange.srp._didInitKnownGroups = !0
    },
    _knownGroupSizes: [1024, 1536, 2048],
    _knownGroups: {
      1024: {
        N: "EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE48E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B297BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9AFD5138FE8376435B9FC61D2FC0EB06E3",
        g: 2
      },
      1536: {
        N: "9DEF3CAFB939277AB1F12A8617A47BBBDBA51DF499AC4C80BEEEA9614B19CC4D5F4F5F556E27CBDE51C6A94BE4607A291558903BA0D0F84380B655BB9A22E8DCDF028A7CEC67F0D08134B1C8B97989149B609E0BE3BAB63D47548381DBC5B1FC764E3F4B53DD9DA1158BFD3E2B9C8CF56EDF019539349627DB2FD53D24B7C48665772E437D6C7F8CE442734AF7CCB7AE837C264AE3A9BEB87F8A2FE9B8B5292E5A021FFF5E91479E8CE7A28C2442C6F315180F93499A234DCF76E3FED135F9BB",
        g: 2
      },
      2048: {
        N: "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73",
        g: 2
      }
    }
  };
