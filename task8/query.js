// query all the blocks from: https://testnet.bscscan.com/address/0x5324eab94b236d4d1456edc574363b113cebf09d

const { Web3 } = require("web3");
//const Web3 = require("web3");
const fs = require("fs");
//const web3 = new Web3("BINANCE_TESTNET_RPC_URL");
const web3 = new Web3("https://bsc-testnet.blockpi.network/v1/rpc/public");
const contractAddress = "0x5324eab94b236d4d1456edc574363b113cebf09d";//"0x9223f0630c598a200f99c5d4746531d10319a569"; //
const targetAddress = "0x9223f0630c598a200f99c5d4746531d10319a569"; //
async function callContractFunction(inputString) {
  try {
    const new_methodId = "0x5c880fcb";
    const blocks = [ 
    	44335452, 
    	43153087,
    	43152140, 
    	43152132, 
    	43152014,
    	43149133,
    	43149124,
    	43149119,
    	43148912,
    	43145703,
    	43145529
    ];
    for (let i = 0; i < blocks.length; i++) {
        const blockNumber = blocks[i]
        const newEncodedData = new_methodId + web3.eth.abi.encodeParameters(["address"], [targetAddress]).slice(2);
        console.log(`Sending encodedData:${newEncodedData}`);
        const newData = await web3.eth.call({to: contractAddress, data: newEncodedData}, blockNumber);
        const decodedData = web3.eth.abi.decodeParameter("string", newData);
        const base64DecodedData = Buffer.from(decodedData, "base64").toString("utf-8");
        const filePath =  blockNumber.toString(10) + "_decoded_output.txt";
        fs.writeFileSync(filePath, base64DecodedData);
        console.log(`Saved decoded data to:${filePath}`);
    }
  } catch (error) {
    console.error("Error calling contract function:", error);
  }
}
const inputString = "";
callContractFunction(inputString);

