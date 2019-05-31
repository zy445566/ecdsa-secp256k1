const secp256k1Config = require('./config')['secp256k1'];
const ecc = require('./lib')

let pointG = ecc.num2Point(secp256k1Config.G);


function randPrivateKeyNum() {
    return ecc.getPrivteKeyNumByRand(secp256k1Config.n);
}

function getPublicKeyPoint(privateKeyNum) {
    return ecc.getPointByNum(privateKeyNum,pointG,secp256k1Config.p,secp256k1Config.a);
}

function sign(privateKeyNum,msgDataNum) {
    return ecc.sign(secp256k1Config.n,pointG,secp256k1Config.p,secp256k1Config.a,privateKeyNum,msgDataNum);
}

function verify(publicKeyPoint,signData,msgDataNum) {
    return ecc.verify(secp256k1Config.n,pointG,secp256k1Config.p,secp256k1Config.a,publicKeyPoint,signData,msgDataNum);
}

module.exports = {
    publicKeyNum2Point:ecc.num2Point,
    publicKeyPoint2HexStr:ecc.point2HexStr,
    publicKeyPoint2Num:ecc.point2Num,
    randPrivateKeyNum,
    getPublicKeyPoint,
    sign,
    verify
}