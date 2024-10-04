void init_big_init()
{
  _DWORD *q; // rbx
  __int64 v1; // rax
  _DWORD *a; // rsi
  __int64 v3; // rax
  _DWORD *b; // rdi
  __int64 v5; // rax
  _DWORD *G_x; // rbp
  __int64 v7; // rax
  _DWORD *G_y; // r14
  __int64 v9; // rax
  __int64 curve; // r15
  __int64 curve_h; // rbx
  unsigned __int64 v12; // rax
  unsigned __int64 random; // rbp
  void **Prng; // r14

  q = (_DWORD *)RhpNewFast(&unk_14015B268);
  v1 = to_decrypt_str((__int64)&unk_14013FC68); // "c90102faa48f18b5eac1f76bb40a1b9fb0d841712bbe3e5576a7a56976c2baeca47809765283aa078583e1e65172a3fd"
  BouncyCastle_Crypto_Org_BouncyCastle_Math_BigInteger___ctor_1(q, v1, 16);
  a = (_DWORD *)RhpNewFast(&unk_14015B268);
  v3 = to_decrypt_str((__int64)&unk_14013FA90); // "a079db08ea2470350c182487b50f7707dd46a58a1d160ff79297dcc9bfad6cfc96a81c4a97564118a40331fe0fc1327f"
  BouncyCastle_Crypto_Org_BouncyCastle_Math_BigInteger___ctor_1(a, v3, 16);
  b = (_DWORD *)RhpNewFast(&unk_14015B268);
  v5 = to_decrypt_str((__int64)&unk_14013EEC8); // "9f939c02a7bd7fc263a4cce416f4c575f28d0c1315c4f0c282fca6709a5f9f7f9c251c9eede9eb1baa31602167fa5380"
  BouncyCastle_Crypto_Org_BouncyCastle_Math_BigInteger___ctor_1(b, v5, 16);
  G_x = (_DWORD *)RhpNewFast(&unk_14015B268);
  v7 = to_decrypt_str((__int64)&unk_14013EC18); // "087b5fe3ae6dcfb0e074b40f6208c8f6de4f4f0679d6933796d3b9bd659704fb85452f041fff14cf0e9aa7e45544f9d8"
  BouncyCastle_Crypto_Org_BouncyCastle_Math_BigInteger___ctor_1(G_x, v7, 16);
  G_y = (_DWORD *)RhpNewFast(&unk_14015B268);
  v9 = to_decrypt_str((__int64)&unk_14013E860); // "127425c1d330ed537663e87459eaa1b1b53edfe305f6a79b184b3180033aab190eb9aa003e02e9dbf6d593c5e3b08182"
  BouncyCastle_Crypto_Org_BouncyCastle_Math_BigInteger___ctor_1(G_y, v9, 16);
  curve = RhpNewFast(&unk_14015B618);
  BouncyCastle_Cryptography_Org_BouncyCastle_Math_EC_FpCurve___ctor_1(// FpCurve curve = new FpCurve(q, a, b, null, null);
    curve,
    (__int64)q,
    (__int64)a,
    (__int64)b,
    0LL,
    0LL,
    0);
  if ( qword_140158FC0[-1] )
    to_S_P_CoreLib_System_Runtime_CompilerServices_ClassConstructorRunner__CheckStaticClassConstructionReturnGCStaticBase();
  curve_h = qword_140238A68;
  RhpAssignRefAVLocation((unsigned __int64 *)(qword_140238A68 + 8), curve);
  v12 = (*(__int64 (__fastcall **)(_QWORD, _DWORD *, _DWORD *))(**(_QWORD **)(curve_h + 8)
                                                              + 0x58LL))(// ECPoint G = curve.CreatePoint(G_x, G_y);
          *(_QWORD *)(curve_h + 8),
          G_x,
          G_y);
  RhpAssignRefAVLocation((unsigned __int64 *)(curve_h + 16), v12);
  random = RhpNewFast(&unk_14015B188);
  Prng = BouncyCastle_Crypto_Org_BouncyCastle_Security_SecureRandom__CreatePrng((__int64)&unk_140149B98, 1);// get 0x40 (64) random bytes
  S_P_CoreLib_System_Random___ctor_0(random, 0LL);
  RhpAssignRefAVLocation((unsigned __int64 *)(random + 16), (unsigned __int64)Prng);
  RhpAssignRefAVLocation((unsigned __int64 *)(curve_h + 24), random);
}

__int64 maybe_main_stuff()
{
  __int64 maybe_curve; // rbx
  _DWORD *xor_key; // rsi
  __int64 v2; // rax
  __int64 maybe_session_key; // rdi
  __int64 v4; // rax
  __int64 some_res; // rax
  __int64 some_res_1; // rbp
  BOOL v7; // ecx
  __int64 block; // r14
  __int64 v9; // rax
  __int64 v10; // rax
  __int64 bInt1; // rax
  __int64 v12; // rcx
  __int64 v13; // rax
  __int64 v14; // rax
  __int64 bInt2; // rax
  __int64 v16; // rcx
  __int64 v17; // rcx
  __int64 v18; // rbp
  __int64 read_val1; // rbp
  __int64 v20; // rcx
  __int64 v21; // r15
  __int64 read_val2; // rax
  __int64 server_PublicKey; // rax
  __int64 v24; // rax
  __int64 v25; // rax
  __int64 v26; // rcx
  BOOL v27; // eax
  __int64 v28; // rax
  __int64 v29; // rax
  unsigned __int64 hash512; // rax
  __int64 v31; // rdx
  unsigned __int64 random_blob; // rsi
  __int64 v33; // rcx
  unsigned __int64 v34; // rbp
  unsigned __int64 v35; // r14
  unsigned __int64 chacha_key; // rax
  __int128 v37; // xmm1
  __int64 v38; // rbp
  unsigned __int64 chacha_nonce; // rax
  void *v40; // rbx
  __int64 v41; // rax
  __int64 v42; // rax
  __int64 v44; // r15
  __int64 v45; // rax
  __int64 v46; // rbx
  __int64 v47; // rax
  __int64 v48; // rbx
  __int64 v49; // rax
  __int64 v50; // rbx
  __int64 v51; // rax
  __int64 v52; // [rsp+38h] [rbp-50h] BYREF
  __int128 v53; // [rsp+40h] [rbp-48h] BYREF
  __int64 v54; // [rsp+50h] [rbp-38h]

  v52 = 0LL;
  v53 = 0LL;
  v54 = 0LL;
  if ( qword_140158FC0[-1] )
    to_S_P_CoreLib_System_Runtime_CompilerServices_ClassConstructorRunner__CheckStaticClassConstructionReturnGCStaticBase();
  maybe_curve = qword_140238A68;

  xor_key = (_DWORD *)RhpNewFast(&unk_14015B268);
  v2 = to_decrypt_str((__int64)&unk_14013E9F8); // L"133713371337133713371337133713371337133713371337133713371337133713371337133713371337133713371337"
  BouncyCastle_Crypto_Org_BouncyCastle_Math_BigInteger___ctor_1(xor_key, v2, 16);
  if ( !*(_QWORD *)(maybe_curve + 16) || !*(_QWORD *)(maybe_curve + 40) )
  {
    v44 = RhpNewFast(&g_vtable1);
    v45 = to_decrypt_str((__int64)&unk_14013FF20);
    BouncyCastle_Crypto_Org_BouncyCastle_Asn1_Asn1ParsingException___ctor_0(v44, v45);
    RhpThrowEx(v44);
  }
  maybe_session_key = some_number_init(128);
  v4 = (*(__int64 (__fastcall **)(_QWORD, __int64))(**(_QWORD **)(maybe_curve + 16)
                                                  + 224LL))(// G.Multiply(sessionKey)
         *(_QWORD *)(maybe_curve + 16),
         maybe_session_key);                    // 140077110
  some_res = (*(__int64 (__fastcall **)(__int64))(*(_QWORD *)v4 + 136LL))(v4);// 140076990
  some_res_1 = some_res;
  if ( *(_QWORD *)(some_res + 16) )
    v7 = 0;
  else
    v7 = *(_QWORD *)(some_res + 24) == 0LL;
  if ( v7 )
  {
    v46 = RhpNewFast(&g_vtable1);
    v47 = to_decrypt_str((__int64)&unk_14013FF48);// "err"
    BouncyCastle_Crypto_Org_BouncyCastle_Asn1_Asn1ParsingException___ctor_0(v46, v47);
    RhpThrowEx(v46);
  }
  block = RhpNewArray(word_14018B688, 0x30uLL);
  v9 = (*(__int64 (__fastcall **)(__int64))(*(_QWORD *)some_res_1 + 80LL))(some_res_1);
  v10 = (*(__int64 (__fastcall **)(__int64))(*(_QWORD *)v9 + 48LL))(v9);// Fetch coordinate
  bInt1 = BouncyCastle_Crypto_Org_BouncyCastle_Math_BigInteger__Xor(v10, xor_key);
  *((_QWORD *)&v53 + 1) = block + 16;
  LODWORD(v54) = 48;
  BouncyCastle_Cryptography_Org_BouncyCastle_Math_BigInteger__ToByteArray_2(bInt1, 1, (__int64)&v53 + 8);
  v12 = *(_QWORD *)(maybe_curve + 40);
  v52 = block + 16;
  LODWORD(v53) = 48;
  System_Net_Sockets_System_Net_Sockets_NetworkStream__Write_0(v12, &v52);// Send coordinate X

  v13 = (*(__int64 (__fastcall **)(__int64))(*(_QWORD *)some_res_1 + 88LL))(some_res_1);
  v14 = (*(__int64 (__fastcall **)(__int64))(*(_QWORD *)v13 + 48LL))(v13);// Fetch coordinate
  bInt2 = BouncyCastle_Crypto_Org_BouncyCastle_Math_BigInteger__Xor(v14, xor_key);
  *((_QWORD *)&v53 + 1) = block + 16;
  LODWORD(v54) = 48;
  BouncyCastle_Cryptography_Org_BouncyCastle_Math_BigInteger__ToByteArray_2(bInt2, 1, (__int64)&v53 + 8);
  v16 = *(_QWORD *)(maybe_curve + 40);
  v52 = block + 16;
  LODWORD(v53) = 48;
  System_Net_Sockets_System_Net_Sockets_NetworkStream__Write_0(v16, &v52);// Send coordinate Y

  v17 = *(_QWORD *)(maybe_curve + 40);
  *((_QWORD *)&v53 + 1) = block + 16;
  LODWORD(v54) = 48;
  System_Net_Sockets_System_Net_Sockets_NetworkStream__Read_0(v17, (__int64)&v53 + 8);
  v18 = RhpNewFast(&unk_14015B268);
  if ( *(&qword_140158AC8 - 1) )
    sub_140001454();
  BouncyCastle_Cryptography_Org_BouncyCastle_Math_BigInteger___ctor_9(v18, 1LL, block, 0, 48u, 1);
  read_val1 = BouncyCastle_Crypto_Org_BouncyCastle_Math_BigInteger__Xor(v18, xor_key);

  v20 = *(_QWORD *)(maybe_curve + 40);
  *((_QWORD *)&v53 + 1) = block + 16;
  LODWORD(v54) = 48;
  System_Net_Sockets_System_Net_Sockets_NetworkStream__Read_0(v20, (__int64)&v53 + 8);
  v21 = RhpNewFast(&unk_14015B268);
  BouncyCastle_Cryptography_Org_BouncyCastle_Math_BigInteger___ctor_9(v21, 1LL, block, 0, 48u, 1);
  read_val2 = BouncyCastle_Crypto_Org_BouncyCastle_Math_BigInteger__Xor(v21, xor_key);

  server_PublicKey = (*(__int64 (__fastcall **)(_QWORD, __int64, __int64))(**(_QWORD **)(maybe_curve + 8)// curve.CreatePoint
                                                                         + 0x50LL))(// 1400748F0
                       *(_QWORD *)(maybe_curve + 8),
                       read_val1,
                       read_val2);
  v24 = (*(__int64 (__fastcall **)(__int64, __int64))(*(_QWORD *)server_PublicKey// Multiply
                                                    + 224LL))(// 140077110
          server_PublicKey,
          maybe_session_key);
  v25 = (*(__int64 (__fastcall **)(__int64))(*(_QWORD *)v24 + 136LL))(v24);// 140076990
  v26 = v25;
  if ( *(_QWORD *)(v25 + 16) )
    v27 = 0;
  else
    v27 = *(_QWORD *)(v25 + 24) == 0LL;
  if ( v27 )
  {
    v48 = RhpNewFast(&g_vtable1);
    v49 = to_decrypt_str((__int64)&unk_14013FF48);// // "err"
    BouncyCastle_Crypto_Org_BouncyCastle_Asn1_Asn1ParsingException___ctor_0(v48, v49);
    RhpThrowEx(v48);
  }
  v28 = (*(__int64 (__fastcall **)(__int64))(*(_QWORD *)v26 + 80LL))(v26);// 140076870
  v29 = (*(__int64 (__fastcall **)(__int64))(*(_QWORD *)v28 + 48LL))(v28);// 140075DF0
  *((_QWORD *)&v53 + 1) = block + 16;
  LODWORD(v54) = 48;
  BouncyCastle_Cryptography_Org_BouncyCastle_Math_BigInteger__ToByteArray_2(v29, 1, (__int64)&v53 + 8);
  hash512 = to_hash_512_val(block);
  if ( hash512 )
  {
    random_blob = hash512 + 0x10;
    v33 = *(unsigned int *)(hash512 + 8);
  }
  else
  {
    random_blob = 0LL;
    v33 = 0LL;
  }
  if ( (unsigned int)v33 < 0x28 )
    BouncyCastle_Crypto_Org_BouncyCastle_Utilities_Collections_UnmodifiableDictionary__Add_1(v33, v31);
  v34 = RhpNewFast(&unk_14015C6C0);
  if ( *((_QWORD *)&unk_140158AF8 - 1) )
    sub_1400010AE();
  BouncyCastle_Cryptography_Org_BouncyCastle_Crypto_Engines_Salsa20Engine___ctor_0(v34, unk_140158AF8);
  RhpAssignRefAVLocation((unsigned __int64 *)(maybe_curve + 48), v34);
  v35 = RhpNewFast(&unk_14015C5B8);
  chacha_key = RhpNewArray(word_14018B688, 0x20uLL);// sha512[0:32] -> Chacha key
  v37 = *(_OWORD *)(random_blob + 16);
  *(_OWORD *)(chacha_key + 16) = *(_OWORD *)random_blob;// key address
  *(_OWORD *)(chacha_key + 32) = v37;
  RhpAssignRefAVLocation((unsigned __int64 *)(v35 + 8), chacha_key);
  v38 = RhpNewFast(&unk_14015C610);
  RhpAssignRefAVLocation((unsigned __int64 *)(v38 + 8), v35);
  chacha_nonce = RhpNewArray(word_14018B688, 8uLL);
  *(_QWORD *)(chacha_nonce + 16) = *(_QWORD *)(random_blob + 32);// sha512[32:32+8] -> Chacha nonce
  RhpAssignRefAVLocation((unsigned __int64 *)(v38 + 16), chacha_nonce);
  qword_14015A6C0(*(_QWORD *)(maybe_curve + 48), 1LL, v38);
  v40 = recv_xor_with_chacha_stream_and_to_unicode();
  v41 = to_decrypt_str((__int64)&qword_140140100);// "verify"
  if ( !(unsigned int)String__Equals_0((__int64)v40, v41) )
  {
    v50 = RhpNewFast(&g_vtable1);
    v51 = to_decrypt_str((__int64)&unk_140140130);// "verify failed"
    BouncyCastle_Crypto_Org_BouncyCastle_Asn1_Asn1ParsingException___ctor_0(v50, v51);
    RhpThrowEx(v50);
  }
  v42 = to_decrypt_str((__int64)&qword_140140100);
  return command_loop(v42);
}
