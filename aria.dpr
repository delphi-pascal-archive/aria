(*******************************************************************

ARIA is a block cipher designed in 2003 by a large
group of South Korean researchers. In 2004, the Korean Agency
for Technology and Standards selected it as a standard
cryptographic technique.

(C) Implemented in pascal by Alexander Myasnikow, 2009

Web: www.darksoftware.narod.ru

********************************************************************)


library aria;

uses
  SysUtils;

type
  u32 = longword;
type
  u8 = byte;

type
  TLongWordArray = array [0..255] of longword;
type
  PLongwordArray = ^TLongWordArray;


const
  S: array[0..3, 0..255] of u8 = (
    // S-box type 1
    (
    $63, $7c, $77, $7b, $f2, $6b, $6f, $c5, $30, $01, $67, $2b,
    $fe, $d7, $ab, $76, $ca, $82, $c9, $7d, $fa, $59, $47, $f0,
    $ad, $d4, $a2, $af, $9c, $a4, $72, $c0, $b7, $fd, $93, $26,
    $36, $3f, $f7, $cc, $34, $a5, $e5, $f1, $71, $d8, $31, $15,
    $04, $c7, $23, $c3, $18, $96, $05, $9a, $07, $12, $80, $e2,
    $eb, $27, $b2, $75, $09, $83, $2c, $1a, $1b, $6e, $5a, $a0,
    $52, $3b, $d6, $b3, $29, $e3, $2f, $84, $53, $d1, $00, $ed,
    $20, $fc, $b1, $5b, $6a, $cb, $be, $39, $4a, $4c, $58, $cf,
    $d0, $ef, $aa, $fb, $43, $4d, $33, $85, $45, $f9, $02, $7f,
    $50, $3c, $9f, $a8, $51, $a3, $40, $8f, $92, $9d, $38, $f5,
    $bc, $b6, $da, $21, $10, $ff, $f3, $d2, $cd, $0c, $13, $ec,
    $5f, $97, $44, $17, $c4, $a7, $7e, $3d, $64, $5d, $19, $73,
    $60, $81, $4f, $dc, $22, $2a, $90, $88, $46, $ee, $b8, $14,
    $de, $5e, $0b, $db, $e0, $32, $3a, $0a, $49, $06, $24, $5c,
    $c2, $d3, $ac, $62, $91, $95, $e4, $79, $e7, $c8, $37, $6d,
    $8d, $d5, $4e, $a9, $6c, $56, $f4, $ea, $65, $7a, $ae, $08,
    $ba, $78, $25, $2e, $1c, $a6, $b4, $c6, $e8, $dd, $74, $1f,
    $4b, $bd, $8b, $8a, $70, $3e, $b5, $66, $48, $03, $f6, $0e,
    $61, $35, $57, $b9, $86, $c1, $1d, $9e, $e1, $f8, $98, $11,
    $69, $d9, $8e, $94, $9b, $1e, $87, $e9, $ce, $55, $28, $df,
    $8c, $a1, $89, $0d, $bf, $e6, $42, $68, $41, $99, $2d, $0f,
    $b0, $54, $bb, $16),
    // S-box type 2
    (
    $e2, $4e, $54, $fc, $94, $c2, $4a, $cc, $62, $0d, $6a, $46,
    $3c, $4d, $8b, $d1, $5e, $fa, $64, $cb, $b4, $97, $be, $2b,
    $bc, $77, $2e, $03, $d3, $19, $59, $c1, $1d, $06, $41, $6b,
    $55, $f0, $99, $69, $ea, $9c, $18, $ae, $63, $df, $e7, $bb,
    $00, $73, $66, $fb, $96, $4c, $85, $e4, $3a, $09, $45, $aa,
    $0f, $ee, $10, $eb, $2d, $7f, $f4, $29, $ac, $cf, $ad, $91,
    $8d, $78, $c8, $95, $f9, $2f, $ce, $cd, $08, $7a, $88, $38,
    $5c, $83, $2a, $28, $47, $db, $b8, $c7, $93, $a4, $12, $53,
    $ff, $87, $0e, $31, $36, $21, $58, $48, $01, $8e, $37, $74,
    $32, $ca, $e9, $b1, $b7, $ab, $0c, $d7, $c4, $56, $42, $26,
    $07, $98, $60, $d9, $b6, $b9, $11, $40, $ec, $20, $8c, $bd,
    $a0, $c9, $84, $04, $49, $23, $f1, $4f, $50, $1f, $13, $dc,
    $d8, $c0, $9e, $57, $e3, $c3, $7b, $65, $3b, $02, $8f, $3e,
    $e8, $25, $92, $e5, $15, $dd, $fd, $17, $a9, $bf, $d4, $9a,
    $7e, $c5, $39, $67, $fe, $76, $9d, $43, $a7, $e1, $d0, $f5,
    $68, $f2, $1b, $34, $70, $05, $a3, $8a, $d5, $79, $86, $a8,
    $30, $c6, $51, $4b, $1e, $a6, $27, $f6, $35, $d2, $6e, $24,
    $16, $82, $5f, $da, $e6, $75, $a2, $ef, $2c, $b2, $1c, $9f,
    $5d, $6f, $80, $0a, $72, $44, $9b, $6c, $90, $0b, $5b, $33,
    $7d, $5a, $52, $f3, $61, $a1, $f7, $b0, $d6, $3f, $7c, $6d,
    $ed, $14, $e0, $a5, $3d, $22, $b3, $f8, $89, $de, $71, $1a,
    $af, $ba, $b5, $81),
    // inverse of S-box type 1
    (
    $52, $09, $6a, $d5, $30, $36, $a5, $38, $bf, $40, $a3, $9e,
    $81, $f3, $d7, $fb, $7c, $e3, $39, $82, $9b, $2f, $ff, $87,
    $34, $8e, $43, $44, $c4, $de, $e9, $cb, $54, $7b, $94, $32,
    $a6, $c2, $23, $3d, $ee, $4c, $95, $0b, $42, $fa, $c3, $4e,
    $08, $2e, $a1, $66, $28, $d9, $24, $b2, $76, $5b, $a2, $49,
    $6d, $8b, $d1, $25, $72, $f8, $f6, $64, $86, $68, $98, $16,
    $d4, $a4, $5c, $cc, $5d, $65, $b6, $92, $6c, $70, $48, $50,
    $fd, $ed, $b9, $da, $5e, $15, $46, $57, $a7, $8d, $9d, $84,
    $90, $d8, $ab, $00, $8c, $bc, $d3, $0a, $f7, $e4, $58, $05,
    $b8, $b3, $45, $06, $d0, $2c, $1e, $8f, $ca, $3f, $0f, $02,
    $c1, $af, $bd, $03, $01, $13, $8a, $6b, $3a, $91, $11, $41,
    $4f, $67, $dc, $ea, $97, $f2, $cf, $ce, $f0, $b4, $e6, $73,
    $96, $ac, $74, $22, $e7, $ad, $35, $85, $e2, $f9, $37, $e8,
    $1c, $75, $df, $6e, $47, $f1, $1a, $71, $1d, $29, $c5, $89,
    $6f, $b7, $62, $0e, $aa, $18, $be, $1b, $fc, $56, $3e, $4b,
    $c6, $d2, $79, $20, $9a, $db, $c0, $fe, $78, $cd, $5a, $f4,
    $1f, $dd, $a8, $33, $88, $07, $c7, $31, $b1, $12, $10, $59,
    $27, $80, $ec, $5f, $60, $51, $7f, $a9, $19, $b5, $4a, $0d,
    $2d, $e5, $7a, $9f, $93, $c9, $9c, $ef, $a0, $e0, $3b, $4d,
    $ae, $2a, $f5, $b0, $c8, $eb, $bb, $3c, $83, $53, $99, $61,
    $17, $2b, $04, $7e, $ba, $77, $d6, $26, $e1, $69, $14, $63,
    $55, $21, $0c, $7d),
    // inverse of S-box type 2
    (
    $30, $68, $99, $1b, $87, $b9, $21, $78, $50, $39, $db, $e1,
    $72, $09, $62, $3c, $3e, $7e, $5e, $8e, $f1, $a0, $cc, $a3,
    $2a, $1d, $fb, $b6, $d6, $20, $c4, $8d, $81, $65, $f5, $89,
    $cb, $9d, $77, $c6, $57, $43, $56, $17, $d4, $40, $1a, $4d,
    $c0, $63, $6c, $e3, $b7, $c8, $64, $6a, $53, $aa, $38, $98,
    $0c, $f4, $9b, $ed, $7f, $22, $76, $af, $dd, $3a, $0b, $58,
    $67, $88, $06, $c3, $35, $0d, $01, $8b, $8c, $c2, $e6, $5f,
    $02, $24, $75, $93, $66, $1e, $e5, $e2, $54, $d8, $10, $ce,
    $7a, $e8, $08, $2c, $12, $97, $32, $ab, $b4, $27, $0a, $23,
    $df, $ef, $ca, $d9, $b8, $fa, $dc, $31, $6b, $d1, $ad, $19,
    $49, $bd, $51, $96, $ee, $e4, $a8, $41, $da, $ff, $cd, $55,
    $86, $36, $be, $61, $52, $f8, $bb, $0e, $82, $48, $69, $9a,
    $e0, $47, $9e, $5c, $04, $4b, $34, $15, $79, $26, $a7, $de,
    $29, $ae, $92, $d7, $84, $e9, $d2, $ba, $5d, $f3, $c5, $b0,
    $bf, $a4, $3b, $71, $44, $46, $2b, $fc, $eb, $6f, $d5, $f6,
    $14, $fe, $7c, $70, $5a, $7d, $fd, $2f, $18, $83, $16, $a5,
    $91, $1f, $05, $95, $74, $a9, $c1, $5b, $4a, $85, $6d, $13,
    $07, $4f, $4e, $45, $b2, $0f, $c9, $1c, $a6, $bc, $ec, $73,
    $90, $7b, $cf, $59, $8f, $a1, $f9, $2d, $f2, $b1, $00, $94,
    $37, $9f, $d0, $2e, $9c, $6e, $28, $3f, $80, $f0, $3d, $d3,
    $25, $8a, $b5, $e7, $42, $b3, $c7, $ea, $f7, $4c, $11, $33,
    $03, $a2, $ac, $60));

const
  KRK: array [0..2, 0..15] of u8 = (
    ($51, $7c, $c1, $b7, $27, $22, $0a, $94, $fe, $13, $ab, $e8,
    $fa, $9a, $6e, $e0),
    ($6d, $b1, $4a, $cc, $9e, $21, $c8, $20, $ff, $28, $b1, $d5,
    $ef, $5d, $e2, $b0),
    ($db, $92, $37, $1d, $21, $26, $e9, $70, $03, $24, $97, $75,
    $04, $e8, $c9, $0e));

  procedure DL(const i: PByteArray; o: PByteArray);
  var
    T: u8;
  begin

    T      := i^ [3] xor i^ [4] xor i^ [9] xor i^ [14];
    o^[0]  := i^ [6] xor i^ [8] xor i^ [13] xor T;
    o^[5]  := i^ [1] xor i^ [10] xor i^ [15] xor T;
    o^[11] := i^ [2] xor i^ [7] xor i^ [12] xor T;
    o^[14] := i^ [0] xor i^ [5] xor i^ [11] xor T;
    T      := i^ [2] xor i^ [5] xor i^ [8] xor i^ [15];
    o^[1]  := i^ [7] xor i^ [9] xor i^ [12] xor T;
    o^[4]  := i^ [0] xor i^ [11] xor i^ [14] xor T;
    o^[10] := i^ [3] xor i^ [6] xor i^ [13] xor T;
    o^[15] := i^ [1] xor i^ [4] xor i^ [10] xor T;
    T      := i^ [1] xor i^ [6] xor i^ [11] xor i^ [12];
    o^[2]  := i^ [4] xor i^ [10] xor i^ [15] xor T;
    o^[7]  := i^ [3] xor i^ [8] xor i^ [13] xor T;
    o^[9]  := i^ [0] xor i^ [5] xor i^ [14] xor T;
    o^[12] := i^ [2] xor i^ [7] xor i^ [9] xor T;
    T      := i^ [0] xor i^ [7] xor i^ [10] xor i^ [13];
    o^[3]  := i^ [5] xor i^ [11] xor i^ [14] xor T;
    o^[6]  := i^ [2] xor i^ [9] xor i^ [12] xor T;
    o^[8]  := i^ [1] xor i^ [4] xor i^ [15] xor T;
    o^[13] := i^ [3] xor i^ [6] xor i^ [8] xor T;
  end;

  procedure RotXOR(const s: PByteArray; n: u32; t: PByteArray);
  var
    i, q: u32;
  begin
    q := n div 8;
    n := n mod 8;
    for i := 0 to 15 do
    begin
      t^[(q + i) mod 16] := t^ [(q + i) mod 16] xor (s^ [i] shr n);
      if (n <> 0) then
        t^[(q + i + 1) mod 16] :=
          u8(t^ [(q + i + 1) mod 16] xor (s^ [i] shl (8 - n)));

    end;
  end;

  function EncKeySetup(const w0, e: PByteArray; keyBits: u32): u32;
  var
    i, R, q: u32;
    t, w1, w2, w3: array [0..15] of u8;
  begin

    R := (keyBits + 256) div 32;
    q := (keyBits - 128) div 64;

    for i := 0 to 15 do
      t[i] := S[i mod 4] [KRK[q] [i] xor w0^ [i]];

    DL(@t, @w1);
    if (R = 14) then
    begin
      for i := 0 to 7 do
        w1[i] := w1[i] xor w0^ [16 + i];
    end
    else
    if (R = 16) then
    begin
      for i := 0 to 15 do
        w1[i] := w1[i] xor w0^ [16 + i];
    end;

    if q = 2 then
      q := 0
    else
      q := q + 1;

    for i := 0 to 15 do
      t[i] := S[(2 + i) mod 4] [KRK[q] [i] xor w1[i]];
    DL(@t, @w2);

    for i := 0 to 15 do
      w2[i] := w2[i] xor w0^ [i];

    if q = 2 then
      q := 0
    else
      q := q + 1;

    for i := 0 to 15 do
      t[i] := S[i mod 4] [KRK[q] [i] xor w2[i]];
    DL(@t, @w3);
    for i := 0 to 15 do
      w3[i] := w3[i] xor w1[i];

    for i := 0 to (16 * (R + 1)) - 1 do
      e^[i] := 0;

    RotXOR(w0, 0, e);
    RotXOR(@w1, 19, e);
    RotXOR(@w1, 0, @e^ [16]);
    RotXOR(@w2, 19, @e^ [16]);
    RotXOR(@w2, 0, @e^ [32]);
    RotXOR(@w3, 19, @e^ [32]);
    RotXOR(@w3, 0, @e^ [48]);
    RotXOR(w0, 19, @e^ [48]);
    RotXOR(w0, 0, @e^ [64]);
    RotXOR(@w1, 31, @e^ [64]);
    RotXOR(@w1, 0, @e^ [80]);
    RotXOR(@w2, 31, @e^ [80]);
    RotXOR(@w2, 0, @e^ [96]);
    RotXOR(@w3, 31, @e^ [96]);
    RotXOR(@w3, 0, @e^ [112]);
    RotXOR(w0, 31, @e^ [112]);
    RotXOR(w0, 0, @e^ [128]);
    RotXOR(@w1, 67, @e^ [128]);
    RotXOR(@w1, 0, @e^ [144]);
    RotXOR(@w2, 67, @e^ [144]);
    RotXOR(@w2, 0, @e^ [160]);
    RotXOR(@w3, 67, @e^ [160]);
    RotXOR(@w3, 0, @e^ [176]);
    RotXOR(w0, 67, @e^ [176]);
    RotXOR(w0, 0, @e^ [192]);
    RotXOR(@w1, 97, @e^ [192]);
    if (R > 12) then
    begin
      RotXOR(@w1, 0, @e^ [208]);
      RotXOR(@w2, 97, @e^ [208]);
      RotXOR(@w2, 0, @e^ [224]);
      RotXOR(@w3, 97, @e^ [224]);
    end;
    if (R > 14) then
    begin
      RotXOR(@w3, 0, @e^ [240]);
      RotXOR(w0, 97, @e^ [240]);
      RotXOR(w0, 0, @e^ [256]);
      RotXOR(@w1, 109, @e^ [256]);
    end;

    Result := R;

  end;

  procedure DecKeySetup(const w0, d: PByteArray; keyBits: u32);
  var
    i, j, R: u32;
    t: array [0..15] of u8;
  begin

    R := EncKeySetup(w0, d, keyBits);

    for j := 0 to 15 do
    begin
      t[j]  := d^ [j];
      d^[j] := d^ [16 * R + j];
      d^[16 * R + j] := t[j];

    end;

    for i := 1 to R div 2 do
    begin
      DL(@d^ [i * 16], @t);
      DL(@d^ [(R - i) * 16], @d^ [i * 16]);


      for j := 0 to 15 do
        d^[(R - i) * 16 + j] := t[j];

    end;

  end;


  procedure AriaCrypt(const p: PByteArray; R: u32; const e: PByteArray;
    c: PByteArray);
  var
    i, j, ep: u32;
    t: array [0..15] of u8;
  begin

    for j := 0 to 15 do
      c^[j] := p^ [j];

    ep := 0;

    for i := 0 to (R div 2) - 1 do
    begin
      for j := 0 to 15 do
        t[j] := S[j mod 4] [e^ [ep + j] xor c^ [j]];
      DL(@t, c);
      ep := ep + 16;
      for j := 0 to 15 do
        t[j] := S[(2 + j) mod 4] [e^ [ep + j] xor c^ [j]];
      DL(@t, c);
      ep := ep + 16;
    end;
    DL(c, @t);
    for j := 0 to 15 do
      c^[j] := e^ [ep + j] xor t[j];
  end;




var
  rk: array [0..(16 * 17) - 1] of u8;
  dk: array [0..(16 * 17) - 1] of u8;




  procedure setup(key: PByteArray); stdcall; export;
  begin
    EncKeySetup(key, @rk, 256);
    DecKeySetup(key, @dk, 256);

  end;



  procedure crypt(from: PByteArray); stdcall; export;
  var
    i: u32;
    t: array [0..15] of u8;
  begin

    AriaCrypt(from, 16, @rk, @t);

    for i := 0 to 15 do
      from^[i] := t[i];

  end;

  procedure decrypt(from: PByteArray); stdcall; export;
  var
    i: u32;
    t: array [0..15] of u8;
  begin

    AriaCrypt(from, 16, @dk, @t);

    for i := 0 to 15 do
      from^[i] := t[i];

  end;


  function getblocksize(): u32; stdcall; export;
  begin
    Result := 128;
  end;

  function getkeysize(): u32; stdcall; export;
  begin
    Result := 256;
  end;

  procedure getciphername(p: PChar); stdcall; export;
  begin
    StrPCopy(p, 'ARIA-256-PAS');
  end;


exports
  setup,
  crypt,
  decrypt,
  getciphername,
  getkeysize,
  getblocksize;

end.
