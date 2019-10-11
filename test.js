// 主网测试私钥原值：eddbdc1168f1daeadbd3e44c1e3f8f5a284c2029f78ad26af98583a499de5b19
// 主网测试私钥值：5Kd3NBUAdUnhyzenEwVLy9pBKxSwXvE9FMPyR4UKZvpe6E3AgLr
// 主网测试公钥原值：04ea279824636aa9172473b6c3076727f17dada14847305487405a38a09c91ce6d63478f426ddcf618be66568cb6bd5bd7201c71689705d9602ae0a7c131a3bafb
// 主网测试地址值：1CH9yicUdqhrxL2EHmHaZMDxtPJ3YM3Kzm
const assert = require('assert');
const crypto = require('crypto');
const ecdsa = require('./index.js');
const secp256k1Config = require('./config')['secp256k1'];
let testUnit = {
    [Symbol('test.publicKeyNum2Point')] : async function() {
        let publicKeyNum = 0x04ea279824636aa9172473b6c3076727f17dada14847305487405a38a09c91ce6d63478f426ddcf618be66568cb6bd5bd7201c71689705d9602ae0a7c131a3bafbn;
        let publicKeyPoint = ecdsa.publicKeyNum2Point(publicKeyNum);
        assert.deepStrictEqual(publicKeyPoint,{
            x: 0xea279824636aa9172473b6c3076727f17dada14847305487405a38a09c91ce6dn,
            y: 0x63478f426ddcf618be66568cb6bd5bd7201c71689705d9602ae0a7c131a3bafbn
        },'publicKeyNum2Point error!')
    },
    [Symbol('test.publicKeyPoint2HexStr')] : async function() {
        let publicKeyPoint = {
            x: 0xea279824636aa9172473b6c3076727f17dada14847305487405a38a09c91ce6dn,
            y: 0x63478f426ddcf618be66568cb6bd5bd7201c71689705d9602ae0a7c131a3bafbn
        };
        let publicKeyNumHexStr = ecdsa.publicKeyPoint2HexStr(publicKeyPoint);
        assert.strictEqual(publicKeyNumHexStr,
            `0x04ea279824636aa9172473b6c3076727f17dada14847305487405a38a09c91ce6d63478f426ddcf618be66568cb6bd5bd7201c71689705d9602ae0a7c131a3bafb`,
            'publicKeyPoint2HexStr error!'
        );
    },
    [Symbol('test.publicKeyPoint2Num')] : async function() {
        let publicKeyPoint = {
            x: 0xea279824636aa9172473b6c3076727f17dada14847305487405a38a09c91ce6dn,
            y: 0x63478f426ddcf618be66568cb6bd5bd7201c71689705d9602ae0a7c131a3bafbn
        };
        let publicKeyNum = ecdsa.publicKeyPoint2Num(publicKeyPoint);
        assert.strictEqual(
            publicKeyNum,
            0x04ea279824636aa9172473b6c3076727f17dada14847305487405a38a09c91ce6d63478f426ddcf618be66568cb6bd5bd7201c71689705d9602ae0a7c131a3bafbn,
            'publicKeyPoint2Num error!'
        );
    },
    [Symbol('test.randPrivateKeyNum')] : async function() {
        let privateKeyNum = ecdsa.randPrivateKeyNum();
        assert(privateKeyNum>=1n && privateKeyNum<=secp256k1Config.n,
            'randPrivateKeyNum error!'
        );
    },
    [Symbol('test.getPublicKeyPoint')] : async function() {
        let privateKeyNum = 0xeddbdc1168f1daeadbd3e44c1e3f8f5a284c2029f78ad26af98583a499de5b19n;
        let publicKeyPoint = ecdsa.getPublicKeyPoint(privateKeyNum);
        assert.deepStrictEqual(publicKeyPoint,{
            x: 0xea279824636aa9172473b6c3076727f17dada14847305487405a38a09c91ce6dn,
            y: 0x63478f426ddcf618be66568cb6bd5bd7201c71689705d9602ae0a7c131a3bafbn
        },'getPublicKeyPoint error!')
    },
    [Symbol('test.sign')] : async function() {
        let privateKeyNum = 0xeddbdc1168f1daeadbd3e44c1e3f8f5a284c2029f78ad26af98583a499de5b19n;
        let publicKeyPoint = {
            x: 0xea279824636aa9172473b6c3076727f17dada14847305487405a38a09c91ce6dn,
            y: 0x63478f426ddcf618be66568cb6bd5bd7201c71689705d9602ae0a7c131a3bafbn
        }
        let msgData = 'Test Data';
        let sha1 = crypto.createHash('sha256').update(msgData).digest('hex');
        let msgDataNum = BigInt(`0x${sha1}`);
        let signData = ecdsa.sign(privateKeyNum,msgDataNum);
        assert(ecdsa.verify(publicKeyPoint,signData,msgDataNum),'sign error!');
    },
    [Symbol('test.verify')] : async function() {
        let privateKeyNum = 0xeddbdc1168f1daeadbd3e44c1e3f8f5a284c2029f78ad26af98583a499de5b19n;
        let publicKeyPoint = {
            x: 0xea279824636aa9172473b6c3076727f17dada14847305487405a38a09c91ce6dn,
            y: 0x63478f426ddcf618be66568cb6bd5bd7201c71689705d9602ae0a7c131a3bafbn
        }
        let msgData = 'Test Data';
        let sha1 = crypto.createHash('sha256').update(msgData).digest('hex');
        let msgDataNum = BigInt(`0x${sha1}`);
        let signData = ecdsa.sign(privateKeyNum,msgDataNum);
        //  ---Error Date---
        let randNum = function(){return BigInt(Math.round(Math.random()*100000));}
        let publicKeyErrorPoint = {
            x: publicKeyPoint.x+randNum(),
            y: publicKeyPoint.y+randNum(),
        }
        let signErrorData = {
            r:signData.r+randNum(),
            s:signData.s+randNum(),
        }
        let msgDataErrorNum = msgDataNum+randNum();
        //  ---Error Date---
        assert(
            ecdsa.verify(publicKeyPoint,signData,msgDataNum) === true 
            && ecdsa.verify(publicKeyErrorPoint,signData,msgDataNum)===false
            && ecdsa.verify(publicKeyPoint,signErrorData,msgDataNum)===false
            && ecdsa.verify(publicKeyPoint,signData,msgDataErrorNum)===false
        ,'verify error!');
    },

    [Symbol('test.publicKeyNum2Point(String)')] : async function() {
        let publicKeyNum = '0x04ea279824636aa9172473b6c3076727f17dada14847305487405a38a09c91ce6d63478f426ddcf618be66568cb6bd5bd7201c71689705d9602ae0a7c131a3bafb';
        let publicKeyPoint = ecdsa.publicKeyNum2Point(publicKeyNum);
        assert.deepStrictEqual(publicKeyPoint,{
            x: 0xea279824636aa9172473b6c3076727f17dada14847305487405a38a09c91ce6dn,
            y: 0x63478f426ddcf618be66568cb6bd5bd7201c71689705d9602ae0a7c131a3bafbn
        },'publicKeyNum2Point(String) error!')
    },
    [Symbol('test.publicKeyPoint2HexStr(String)')] : async function() {
        let publicKeyPoint = {
            x: '0xea279824636aa9172473b6c3076727f17dada14847305487405a38a09c91ce6d',
            y: '0x63478f426ddcf618be66568cb6bd5bd7201c71689705d9602ae0a7c131a3bafb'
        };
        let publicKeyNumHexStr = ecdsa.publicKeyPoint2HexStr(publicKeyPoint);
        assert.strictEqual(publicKeyNumHexStr,
            `0x04ea279824636aa9172473b6c3076727f17dada14847305487405a38a09c91ce6d63478f426ddcf618be66568cb6bd5bd7201c71689705d9602ae0a7c131a3bafb`,
            'publicKeyPoint2HexStr(String) error!'
        );
    },
    [Symbol('test.publicKeyPoint2Num(String)')] : async function() {
        let publicKeyPoint = {
            x: '0xea279824636aa9172473b6c3076727f17dada14847305487405a38a09c91ce6d',
            y: '0x63478f426ddcf618be66568cb6bd5bd7201c71689705d9602ae0a7c131a3bafb'
        };
        let publicKeyNum = ecdsa.publicKeyPoint2Num(publicKeyPoint);
        assert.strictEqual(
            publicKeyNum,
            0x04ea279824636aa9172473b6c3076727f17dada14847305487405a38a09c91ce6d63478f426ddcf618be66568cb6bd5bd7201c71689705d9602ae0a7c131a3bafbn,
            'publicKeyPoint2Num error!'
        );
    },
    [Symbol('test.getPublicKeyPoint(String)')] : async function() {
        let privateKeyNum = '0xeddbdc1168f1daeadbd3e44c1e3f8f5a284c2029f78ad26af98583a499de5b19';
        let publicKeyPoint = ecdsa.getPublicKeyPoint(privateKeyNum);
        assert.deepStrictEqual(publicKeyPoint,{
            x: 0xea279824636aa9172473b6c3076727f17dada14847305487405a38a09c91ce6dn,
            y: 0x63478f426ddcf618be66568cb6bd5bd7201c71689705d9602ae0a7c131a3bafbn
        },'getPublicKeyPoint(String) error!')
    },
    [Symbol('test.sign(String)')] : async function() {
        let privateKeyNum = '0xeddbdc1168f1daeadbd3e44c1e3f8f5a284c2029f78ad26af98583a499de5b19';
        let publicKeyPoint = {
            x: 0xea279824636aa9172473b6c3076727f17dada14847305487405a38a09c91ce6dn,
            y: 0x63478f426ddcf618be66568cb6bd5bd7201c71689705d9602ae0a7c131a3bafbn
        }
        let msgData = 'Test Data';
        let sha1 = crypto.createHash('sha256').update(msgData).digest('hex');
        let msgDataNum = `0x${sha1}`;
        let signData = ecdsa.sign(privateKeyNum,msgDataNum);
        assert(ecdsa.verify(publicKeyPoint,signData,msgDataNum),'sign(String) error!');
    },
    [Symbol('test.verify(String)')] : async function() {
        let privateKeyNum = '0xeddbdc1168f1daeadbd3e44c1e3f8f5a284c2029f78ad26af98583a499de5b19';
        let publicKeyPoint = {
            x: '0xea279824636aa9172473b6c3076727f17dada14847305487405a38a09c91ce6d',
            y: '0x63478f426ddcf618be66568cb6bd5bd7201c71689705d9602ae0a7c131a3bafb'
        }
        let msgData = 'Test Data';
        let sha1 = crypto.createHash('sha256').update(msgData).digest('hex');
        let msgDataNum = `0x${sha1}`;
        let signData = ecdsa.sign(privateKeyNum,msgDataNum);
        //  ---Error Date---
        let randNum = function(){return BigInt(Math.round(Math.random()*100000));}
        let publicKeyErrorPoint = {
            x: (publicKeyPoint.x+randNum()).toString(16),
            y: (publicKeyPoint.y+randNum()).toString(16),
        }
        let signErrorData = {
            r:(signData.r+randNum()).toString(16),
            s:(signData.s+randNum()).toString(16),
        }
        let msgDataErrorNum = msgDataNum+randNum();
        //  ---Error Date---
        assert(
            ecdsa.verify(publicKeyPoint,signData,msgDataNum) === true 
            && ecdsa.verify(publicKeyErrorPoint,signData,msgDataNum)===false
            && ecdsa.verify(publicKeyPoint,signErrorData,msgDataNum)===false
            && ecdsa.verify(publicKeyPoint,signData,msgDataErrorNum)===false
        ,'verify(String) error!');
    },
}

async function run(testUnitList) {
    for(let testUnitValue of testUnitList) {
        for(let testFunc of Object.getOwnPropertySymbols(testUnitValue)) {
            await testUnitValue[testFunc]();
        }
    }
}
run([testUnit]);