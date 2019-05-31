// T = (p, a, b, G, n, h)
// E : y^2 ≡ x^3 + ax + b (mod p)
// 相同的点相加第一式: λ≡(3x1^2+ a)/2y1(mod p)
// 相同的点相加第二式: x3 ≡ λ^2 − 2x1 (mod p), y3≡ λ(x1 − x3) − y1 (mod p)
// 不同的点相加第一式: λ≡ （y2 − y1）/（x2 − x1）(mod p)
// 不同的点相加第二式: x3 ≡ λ^2 − x1 − x2 (mod p), y3 ≡ λ(x1 − x3) − y1 (mod p)
// secp256k1
const config = {
    'secp256k1':{
        p:0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2Fn,
        a:0n,
        b:7n,
        G:0x0479BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8n,
        n:0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n,
        h:1n
    }
}


function num2Point(num){
    let numHex = num.toString(16);
    let len = 129;
    if(numHex.length!=len){
        throw new Error(`point num length must be ${len}!`);
    }
    if(numHex[0]!='4') {
        throw new Error('point num data not right!');
    }
    let startX = 1;
    let startY= 65;
    let offset = 64;
    return {x:BigInt(`0x${numHex.slice(startX,startX+offset)}`),y:BigInt(`0x${numHex.slice(startY,startY+offset)}`)};
}
function point2Num(point) {
    return BigInt(`0x04${point.x.toString(16)}${point.y.toString(16)}`);
}

function postiveMod(num,modNum) {
    return (num%modNum + modNum)%modNum;
}
// 欧几里德算法求乘法逆元
function inverseMulti(x,modNum) {
    let x1= 1n,x2 = 0n,x3 = modNum;
    let y1 = 0n,y2=1n,y3=(x%modNum+modNum)%modNum;
    let q;
    let t1,t2,t3;
    while(true){
        if(y3==0n)return null;
        if(y3==1n)return y2;
        q = x3/y3;
        t1=x1-q*y1;t2=x2-q*y2;t3=x3-q*y3;
        x1=y1;x2=y2;x3=y3;
        y1=t1;y2=t2;y3=t3;
    }
}

function getPrivteOriginKeyByRand(n) {
    let nHex = n.toString(16);
    let privteKeyList = [];
    let isZero = true;
    for(let i=0;i<nHex.length;i++) {
        let rand16Num = Math.round(Math.random()*parseInt(nHex[i],16));
        privteKeyList.push(rand16Num.toString(16));
        if(rand16Num>0) {isZero = false;}
    }
    if(isZero){return getPrivteOriginKeyByRand();}
    return privteKeyList.join('');
}

function addSamePoint(x1,y1,modNum,a) {
    let ru = postiveMod((3n*(x1**2n)+a)*inverseMulti(2n*y1, modNum), modNum);
    let x3 = postiveMod((ru**2n) - (2n*x1), modNum);
    let y3 = postiveMod(ru*(x1-x3) - y1, modNum);
    return {x:x3,y:y3};
}
function addDiffPoint(x1,y1,x2,y2,modNum) {
    let ru = postiveMod((y2-y1)*inverseMulti(x2-x1, modNum), modNum);
    let x3 = postiveMod(ru**2n - x1 - x2, modNum);
    let y3 = postiveMod(ru*(x1-x3)-y1, modNum);
    return {x:x3,y:y3};
}

function getPointByNum(num,pointG,p,a) {
    let numBin = num.toString(2);
    let nowPoint = null;
    let nextPoint = pointG;
    for(let i=numBin.length-1;i>=0;i--) {
        if(numBin[i]=='1') {
            if(nowPoint === null) {
                nowPoint = nextPoint;
            } else {
                nowPoint = addDiffPoint(nowPoint.x,nowPoint.y,nextPoint.x,nextPoint.y,p);
            }
        }
        nextPoint = addSamePoint(nextPoint.x,nextPoint.y,p,a);
    }
    return nowPoint;
}

/**
 * s = k^-1 (e + rd) mod n 
 * M为要签名消息,d为私钥的值
 */
function sign(n,pointG,p,a,d,M,encoding='utf8') {
    let k,R;
    let r = 0n;
    while(r==0n) {
        k = BigInt(`0x${getPrivteOriginKeyByRand(n)}`);
        R = getPointByNum(k,pointG,p,a);
        r = postiveMod(R.x,n);
    }
    let e = BigInt(`0x${Buffer.from(M,encoding).toString('hex')}`);
    let s = postiveMod(((e+(r*d))*inverseMulti(k,n)),n);
    if(s==0n) {
        return sign(n,pointG,p,a,d,M,encoding);
    }
    return {r,s};
}
/**
 * 
 * @param {*} pointQ 为我的公钥原值的点
 */
function verify(n,pointG,p,a,pointQ,S,M,encoding='utf8') {
    let {r,s} = S;
    let e = BigInt(`0x${Buffer.from(M,encoding).toString('hex')}`);
    let w = inverseMulti(s,n);
    let u1 = postiveMod((e*w),n);
    let u2 = postiveMod((r*w),n);
    let u1Point = getPointByNum(u1,pointG,p,a);
    let u2Point = getPointByNum(u2,pointQ,p,a);
    let pointR;
    if(u1Point.x==u2Point.x && u1Point.y==u2Point.y) {
        pointR = addSamePoint(u1Point.x,u1Point.y,p,a);
    } else {
        pointR = addDiffPoint(u1Point.x,u1Point.y,u2Point.x,u2Point.y,p);
    }
    let v = postiveMod(pointR.x,n);
    // console.log(v.toString(16),r.toString(16))
    if(v==r) {
        return true;
    }
    return false;
}

let secp256k1 = config['secp256k1'];
let pointG = num2Point(secp256k1.G);
let key = BigInt(`0x0000000000000000000000000000000000000000000000000000000000000003`);
let publicG = getPointByNum(
    key,
    pointG,secp256k1.p,secp256k1.a
)
let Msg = "Hello";
let S = sign(secp256k1.n,pointG,secp256k1.p,secp256k1.a,key,Msg,'utf8');
// console.log(S.r.toString(16),S.s.toString(16))
console.log(verify(secp256k1.n,pointG,secp256k1.p,secp256k1.a,publicG,S,Msg,'utf8'))

// let pointG2 = addSamePoint(pointG.x,pointG.y,secp256k1.p,secp256k1.a);
// console.log(point2Num(pointG2).toString(16))
// console.log(bgk.getPublicOriginKey('0000000000000000000000000000000000000000000000000000000000000003'))
// //04f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9388f7b0f632de8140fe337e62a37f3566500a99934c2231b6cb9fd7584b8e672
// let pointG3 = addDiffPoint(pointG.x,pointG.y,pointG2.x,pointG2.y,secp256k1.p)
// console.log(point2Num(pointG3).toString(16))
