const {onCall, HttpsError} = require('firebase-functions/v2/https');
const {onDocumentWritten} = require('firebase-functions/v2/firestore');
const {initializeApp} = require('firebase-admin/app');
const {getAuth} = require('firebase-admin/auth');
const {getFirestore, FieldValue} = require('firebase-admin/firestore');
const crypto = require('crypto');
initializeApp();
const db = getFirestore();
const axes = ['اللجنة','اليانور','الرؤية','العنصرية'];
function hashPin(pin,salt){return crypto.scryptSync(pin,salt,64).toString('hex')}
async function adminOnly(req){if(!req.auth)throw new HttpsError('unauthenticated','يلزم تسجيل الدخول.');const user=await db.collection('users').doc(req.auth.uid).get();if(!user.exists||user.data().role!=='admin')throw new HttpsError('permission-denied','هذه العملية للإدارة فقط.')}
exports.loginJudge = onCall({region:'us-central1',maxInstances:10},async req=>{
 const code=String(req.data?.code||'').trim().toUpperCase(),pin=String(req.data?.pin||'');
 if(!/^[A-Z0-9_-]{3,20}$/.test(code)||pin.length<6)throw new HttpsError('invalid-argument','رمز الدخول غير صالح.');
 const ref=db.collection('judges').doc(code),snap=await ref.get();if(!snap.exists||snap.data().active===false)throw new HttpsError('unauthenticated','بيانات الدخول غير صحيحة.');
 const judge=snap.data(),actual=Buffer.from(hashPin(pin,judge.salt),'hex'),expected=Buffer.from(judge.pinHash,'hex');
 if(actual.length!==expected.length||!crypto.timingSafeEqual(actual,expected))throw new HttpsError('unauthenticated','بيانات الدخول غير صحيحة.');
 const uid=`judge_${code}`;await getAuth().getUser(uid).catch(async e=>{if(e.code==='auth/user-not-found')return getAuth().createUser({uid,displayName:judge.name});throw e});
 const token=await getAuth().createCustomToken(uid,{role:'judge',judgeCode:code});return {token};
});
exports.createJudge = onCall({region:'us-central1'},async req=>{
 adminOnly(req);const name=String(req.data?.name||'').trim(),code=String(req.data?.code||'').trim().toUpperCase(),pin=String(req.data?.pin||'');
 if(!name||!/^[A-Z0-9_-]{3,20}$/.test(code)||pin.length<6)throw new HttpsError('invalid-argument','راجعي الاسم والرمز (3–20) ورمز الدخول (6 خانات على الأقل).');
 const ref=db.collection('judges').doc(code),old=await ref.get();if(old.exists)throw new HttpsError('already-exists','رمز المحكّم مستخدم مسبقًا.');
 const salt=crypto.randomBytes(16).toString('hex');await ref.set({name,code,salt,pinHash:hashPin(pin,salt),active:true,createdAt:FieldValue.serverTimestamp()});return {ok:true};
});
exports.saveEvaluation = onCall({region:'us-central1'},async req=>{
 if(!req.auth||req.auth.token.role!=='judge')throw new HttpsError('permission-denied','هذه العملية متاحة للمحكّمين فقط.');
 const participantId=String(req.data?.participantId||''),scores=req.data?.scores;
 if(!participantId||!Array.isArray(scores)||scores.length!==16||scores.some(x=>!Number.isInteger(x)||x<0||x>6))throw new HttpsError('invalid-argument','يجب إدخال 16 درجة من صفر إلى 6.');
 const p=await db.collection('participants').doc(participantId).get();if(!p.exists||p.data().active===false)throw new HttpsError('not-found','المشارك غير موجود.');
 const raw=scores.reduce((a,b)=>a+b,0),normalized=Number((raw/96*100).toFixed(4)),judgeCode=String(req.auth.token.judgeCode||'');
 const id=`${participantId}_${req.auth.uid}`;await db.collection('evaluations').doc(id).set({participantId,participantName:p.data().name,judgeUid:req.auth.uid,judgeCode,scores,rawTotal:raw,normalized,updatedAt:FieldValue.serverTimestamp()},{merge:true});
 return {ok:true,rawTotal:raw,normalized};
});
exports.rebuildPublicResult = onDocumentWritten({document:'evaluations/{evaluationId}',region:'us-central1'},async event=>{
 const after=event.data.after;if(!after.exists)return;const e=after.data(),pid=e.participantId;const [p,all,prior]=await Promise.all([db.collection('participants').doc(pid).get(),db.collection('evaluations').where('participantId','==',pid).get(),db.collection('publicResults').doc(pid).get()]);if(!p.exists)return;
 const vals=all.docs.map(d=>Number(d.data().normalized)||0),avg=vals.length?Number((vals.reduce((a,b)=>a+b,0)/vals.length).toFixed(2)):0;
 await db.collection('publicResults').doc(pid).set({participantId:pid,name:p.data().name,average:avg,evaluationCount:vals.length,published:prior.exists ? prior.data().published===true : false,updatedAt:FieldValue.serverTimestamp()},{merge:true});
});
exports.publishResults = onCall({region:'us-central1'},async req=>{
 adminOnly(req);const snap=await db.collection('publicResults').get();const batch=db.batch();snap.docs.forEach(d=>batch.update(d.ref,{published:true,updatedAt:FieldValue.serverTimestamp()}));await batch.commit();return {count:snap.size};
});
