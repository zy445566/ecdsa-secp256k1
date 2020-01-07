const secp256k1Config = require('./config')['secp256k1'];
const ecc = require('./lib')

let pointG = ecc.num2Point(secp256k1Config.G);

function StringConvertBigNum(num) {
    if(typeof num == 'string') {
        return BigInt(num);
    }
    return num;
}

function randPrivateKeyNum() {
    return ecc.getPrivteKeyNumByRand(secp256k1Config.n);
}

function publicKeyNum2Point(publicKeyNum) {
    return ecc.num2Point(StringConvertBigNum(publicKeyNum));
}

function publicKeyPoint2HexStr(publicKeyPoint) {
    return ecc.point2HexStr({
        x:StringConvertBigNum(publicKeyPoint.x),
        y:StringConvertBigNum(publicKeyPoint.y)
    });
}

function publicKeyPoint2Num(publicKeyPoint) {
    return ecc.point2Num({
        x:StringConvertBigNum(publicKeyPoint.x),
        y:StringConvertBigNum(publicKeyPoint.y)
    });
}


function getPublicKeyPoint(privateKeyNum) {
    return ecc.getPointByNum(
        StringConvertBigNum(privateKeyNum),
        pointG,secp256k1Config.p,secp256k1Config.a
    );
}

function sign(privateKeyNum,msgDataNum) {
    return ecc.sign(
        secp256k1Config.n,pointG,secp256k1Config.p,secp256k1Config.a,
        StringConvertBigNum(privateKeyNum),
        StringConvertBigNum(msgDataNum)
    );
}

function verify(publicKeyPoint,signData,msgDataNum) {
    return ecc.verify(
        secp256k1Config.n,pointG,secp256k1Config.p,secp256k1Config.a,
        {
            x:StringConvertBigNum(publicKeyPoint.x),
            y:StringConvertBigNum(publicKeyPoint.y)
        },
        StringConvertBigNum(signData),
        StringConvertBigNum(msgDataNum)
    );
}
const defaultData = {
    publicKeyNum2Point,
    publicKeyPoint2HexStr,
    publicKeyPoint2Num,
    randPrivateKeyNum,
    getPublicKeyPoint,
    sign,
    verify
}
module.exports = defaultData;
module.exports.default = defaultData;

