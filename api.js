"use strict"; // API created by Ibnu Rizal - Call Me RZ!
const express = require('express');
const bodyParser = require('body-parser');
const app = express();
const app2 = express();
const mysql = require('mysql');
const crypto = require('crypto');
const fs = require('fs');
var moment = require('moment');
var uniqid = require('uniqid');
var helmet = require('helmet');
var sanitizer = require('sanitizer');
const requestIp = require('request-ip');
var http = require("http");
var querystring = require('querystring');
app.use(requestIp.mw())


const conn = mysql.createConnection({
    host: 'localhost',
    user: 'blah_blah_blah_I_change_this_value',
    password: '12345_blah_blah',
    database: 'of_course_I_will_change_this_value'
});

conn.on('error', function (err) {
    console.log("[mysql error]", err);
});

const options = {
    key: fs.readFileSync('secret laahhh'),
    cert: fs.readFileSync('secrett laahhh')
};

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json())
app.use(express.json({ limit: '10kb' })); /* prevent ddos */
app.use(helmet())

const https = require('https');

//if request is blank
app.post('/', (req, res) => {
    res.send(JSON.stringify({ "status": 500, "error": "Rizal is awewsome" }));
});

app.post('/create', (req, res) => {
    /*
    parameter need:
    - partner_key               : You must post partner_key given by us on first time registration
    - customer_phone            : customer phone number
    - token                     : Combination of hash(256) -> DDMMYYYY + partner_key + partner_secret + app_id

    if OK, we will send:
    - message code              : it is 200
    - customer_phone_number     : customer_phone_number
    - otp_code                  : otp_code
    */

    const app_id = 'xxxxxx';
    const partner_key = sanitizer.sanitize(req.body.partner_key);
    const customer_phone_number = sanitizer.sanitize(req.body.customer_phone_number);
    const mytoken = sanitizer.sanitize(req.body.token);
    const no_hp = customer_phone_number.substring(2, 20);
    const account_id = partner_key + no_hp;

    //check if parameter is empty
    if (app_id == null || partner_key == null || customer_phone_number == null || mytoken == null || app_id == '' || partner_key == '' || customer_phone_number == '' || mytoken == '') {
        res.end(JSON.stringify({ "status": 101, "message": "Parameter kosong" }));
    } else {

        /* 23-05-2020
        penambahan check jika user inputnya 0, maka diganti dengan 62, sebaliknya tetap input as is
        */
        let phone_number = '';
        let customer_phone_number2 = customer_phone_number.replace('+', '')
        if (customer_phone_number2.substring(1, 0) == 0) {
            phone_number = 62 + customer_phone_number2.substring(1, 20);
        } else {
            phone_number = customer_phone_number2;
        }

        //check data partner apakah benar di DB apa tidak
        conn.query("SELECT partner_id,partner_key, partner_secret FROM tbl_partner WHERE partner_key = ? LIMIT 1", [partner_key], function (error, results, fields) {
            if (results.length == 0) {
                res.end(JSON.stringify({ "status": 104, "message": 'Data tidak valid' }));
            } else {
                var tanggal = moment().format('DDMMYYYY');
                let partner_secret = results[0].partner_secret;
                let partner_id = results[0].partner_id;
                let gabungan = tanggal + partner_key + partner_secret + app_id;
                const token = crypto.createHash('sha256').update(gabungan).digest('hex');

                if (customer_phone_number.length < 8) { //check apakah nomor hp terlalu pendek?
                    res.end(JSON.stringify({ "status": 110, "message": 'Nomor telepon terlalu pendek. Ini nomor telepon apa kode togel?' }));
                } else {
                    if (token != mytoken) { //check apakah tokennya mismatch?
                        res.end(JSON.stringify({ "status": 102, "message": 'Token salah', 'a': token }));
                    } else {
                        //check apakah customer phone ini sudah pernah didaftarkan atau belum?
                        let sql = "SELECT customer_phone_number FROM tbl_customer WHERE customer_phone_number = ? LIMIT 1";
                        conn.query(sql, [customer_phone_number], (err, results) => {
                            if (results.length > 0) {
                                res.end(JSON.stringify({ "status": 109, "message": "Hei, nomor telepon ini telah terdaftar" }));
                            } else {
                                //delete customer_phone_number and partner_key yang sama biar data nggak banyak
                                let sql_delete = "DELETE FROM tbl_otp WHERE customer_phone_number = ? AND partner_key = ? LIMIT 1";
                                conn.query(sql_delete, [customer_phone_number, partner_key]);

                                //sending an OTP

                                var username = "innolifepremium";
                                var password = "3Jhd7ad4KL";
                                var seq = (Math.floor(Math.random() * 10000) + 10000).toString().substring(1);


                                var dataPost = querystring.stringify({
                                    from: 'INNO',
                                    to: phone_number,
                                    text: 'Hai, kode OTP Inno Anda adalah ' + seq + '. Mohon jangan diberikan kepada siapapun'
                                });

                                var options = {
                                    host: "107.20.199.106",
                                    path: "/restapi/sms/1/text/single/",
                                    method: 'POST',
                                    headers: {
                                        'Content-Type': 'application/x-www-form-urlencoded',
                                        'Content-Length': dataPost.length,
                                        "Authorization": "Basic " + new Buffer(username + ":" + password).toString('base64')
                                    }
                                };

                                var req = http.request(options, function (response) {
                                    console.log(response.statusCode);
                                    console.log(response.statusMessage);
                                    console.log(response.headers);
                                });

                                req.write(dataPost);
                                req.end();

                                let created_date = moment.utc().format('YYYY-MM-DD HH:mm:ss');
                                var post = { customer_phone_number: customer_phone_number, account_id: account_id, partner_key: partner_key, otp_code: seq, created_date: created_date };
                                let sql = "INSERT INTO tbl_otp SET ?";
                                conn.query(sql, post);
                                res.end(JSON.stringify({ "status": 200, "message": "OK", "otp_code": seq }));
                            }
                        });
                    }
                }
            }
        });
    }
});

app.post('/verify', (req, res) => {
    /*
    parameter need:
    - partner_key               : You must post partner_key given by us on first time registration
    - customer_phone            : customer phone number
    - uuid                      : UUID
    - otp_code                  : otp code
    - token                     : Combination of hash(256) -> DDMMYYYY + partner_key + partner_secret + app_id

    if OK, we will send:
    - message code              : it is 200
    */

    const app_id = 'xxx';
    const partner_key = sanitizer.sanitize(req.body.partner_key);
    const uuid = sanitizer.sanitize(req.body.uuid);
    const customer_phone_number = sanitizer.sanitize(req.body.customer_phone_number);
    const otp_code = sanitizer.sanitize(req.body.otp_code);
    const mytoken = sanitizer.sanitize(req.body.token);

    //check if parameter is empty
    if (app_id == null || partner_key == null || customer_phone_number == null || otp_code == null || mytoken == null || uuid == null || app_id == '' || partner_key == '' || customer_phone_number == '' || otp_code == '' || mytoken == '' || uuid == '') {
        res.end(JSON.stringify({ "status": 101, "message": "Parameter kosong seperti hati aku yang hampa" }));
    } else {
        //check data partner apakah benar di DB apa tidak
        conn.query("SELECT partner_id,partner_key, partner_secret FROM tbl_partner WHERE partner_key = ? LIMIT 1", [partner_key], function (error, results, fields) {
            if (results.length == 0) {
                res.end(JSON.stringify({ "status": 104, "message": 'Data Mitra tidak ditemukan' }));
            } else {
                var tanggal = moment().format('DDMMYYYY');
                let partner_secret = results[0].partner_secret;
                let partner_id = results[0].partner_id;
                let gabungan = tanggal + partner_key + partner_secret + app_id;
                const token = crypto.createHash('sha256').update(gabungan).digest('hex');

                if (token != mytoken) { //check apakah tokennya mismatch?
                    res.end(JSON.stringify({ "status": 102, "message": 'Token anda tidak berjodoh dengan token dari kami' }));
                } else {
                    //check apakah customer phone ini sudah pernah didaftarkan atau belum?
                    let sql = "SELECT customer_phone_number FROM tbl_customer WHERE customer_phone_number = ? LIMIT 1";
                    conn.query(sql, [customer_phone_number], (err, results) => {
                        if (results.length > 0) {
                            res.end(JSON.stringify({ "status": 109, "message": "Hei, nomor telepon ini sudah terdaftar lho" }));
                        } else {
                            //check kode otp sama no hp user
                            let sql_check = "SELECT customer_phone_number, otp_code FROM tbl_otp WHERE customer_phone_number = ? AND otp_code = ? LIMIT 1";
                            conn.query(sql_check, [customer_phone_number, otp_code], (err, results) => {
                                if (results.length == 0) {
                                    res.end(JSON.stringify({ "status": 110, "message": "OTP MISMATCH" }));
                                } else {
                                    res.end(JSON.stringify({ "status": 200, "message": "OK" }))
                                }
                            });
                        }
                    });
                }
            }
        });
    }
});

app.post('/createpin', (req, res) => {
    /*
    parameter need:
    - partner_key               : You must post partner_key given by us on first time registration
    - customer_phone            : customer phone number
    - uuid                      : uuid
    - pin1                      : pin1
    - pin2                      : pin2
    - token                     : Combination of hash(256) -> DDMMYYYY + partner_key + partner_secret + app_id
    - handset_type              : get handset type from customer phone

    if OK, we will send:
    - message code              : it is 200
    */

    const app_id = 'xxx';
    const partner_key = sanitizer.sanitize(req.body.partner_key);
    const customer_phone_number = sanitizer.sanitize(req.body.customer_phone_number);
    const uuid = sanitizer.sanitize(req.body.uuid);
    const mytoken = sanitizer.sanitize(req.body.token);
    const pin1 = sanitizer.sanitize(req.body.pin1);
    const pin2 = sanitizer.sanitize(req.body.pin2);
    const handset_type = sanitizer.sanitize(req.body.handset_type);
    const ip = req.clientIp.split(":").pop();

    //check if parameter is empty
    if (app_id == null || partner_key == null || customer_phone_number == null || mytoken == null || uuid == null || pin1 == null || pin2 == null || app_id == '' || partner_key == '' || customer_phone_number == '' || mytoken == '' || uuid == '' || pin1 == '' || pin2 == '') {
        res.end(JSON.stringify({ "status": 101, "message": "Parameter kosong seperti hati aku yang hampa" }));
    } else {

        /* 23-05-2020
        penambahan check jika user inputnya 0, maka diganti dengan 62, sebaliknya tetap input as is
        */
        let phone_number = '';
        let customer_phone_number2 = customer_phone_number.replace('+', '')
        if (customer_phone_number2.substring(1, 0) == 0) {
            phone_number = 62 + customer_phone_number2.substring(1, 20);
        } else {
            phone_number = customer_phone_number2;
        }

        //check data partner apakah benar di DB apa tidak
        conn.query("SELECT partner_id,partner_key, partner_secret FROM tbl_partner WHERE partner_key = ? LIMIT 1", [partner_key], function (error, results, fields) {
            if (results.length == 0) {
                res.end(JSON.stringify({ "status": 104, "message": 'Data Mitra tidak ditemukan' }));
            } else {
                var tanggal = moment().format('DDMMYYYY');
                let partner_secret = results[0].partner_secret;
                let partner_id = results[0].partner_id;
                let gabungan = tanggal + partner_key + partner_secret + app_id;
                const token = crypto.createHash('sha256').update(gabungan).digest('hex');

                if (token != mytoken) { //check apakah tokennya mismatch?
                    res.end(JSON.stringify({ "status": 102, "message": 'Token anda tidak berjodoh dengan token dari kami' }));
                } else {
                    //check apakah customer phone ini sedang login apa blm?
                    let sql = "SELECT customer_phone_number FROM tbl_customer WHERE customer_phone_number = ?  and login_status = 5 LIMIT 1";
                    conn.query(sql, [phone_number], (err, results) => {
                        if (results.length > 0) {
                            res.end(JSON.stringify({ "status": 111, "message": "Anda telah login" }));
                        } else if (pin1.length > 6 || pin2.length < 6) {
                            res.end(JSON.stringify({ "status": 115, "message": "Pin harus 6 digit" }));
                        } else if (pin1 != pin2) {
                            res.end(JSON.stringify({ "status": 118, "message": "Pin tidak sama" }));
                        } else {
                            //check apakah ID customer ada di DB apa tidak
                            let sql = "select customer_phone_number FROM tbl_customer WHERE customer_phone_number = ? AND partner_key = ? LIMIT 1";
                            conn.query(sql, [phone_number, partner_key], (err, results) => {
                                if (results.length > 0) {
                                    res.end(JSON.stringify({ "status": 109, "message": 'Hei, nomor telepon ini sudah terdaftar lho' }));
                                } else {
                                    //create new customer
                                    let created_date = moment.utc().format('YYYY-MM-DD HH:mm:ss');
                                    let pin = crypto.createHash('sha256').update(pin1).digest('hex');
                                    let account_id = partner_key + phone_number;
                                    var post3 = { account_id: account_id, uuid: uuid, customer_pin: pin, customer_phone_number: phone_number, created_date: created_date, partner_key: partner_key, handset_type: handset_type, ip_address: ip };
                                    let sql3 = "INSERT INTO tbl_customer SET ?";
                                    conn.query(sql3, post3)

                                    //input ke customer log
                                    var post_log = { account_id: account_id, customer_phone_number: phone_number, customer_log_action: 'REGISTER', created_date: created_date, partner_key: partner_key, handset_type: handset_type, ip_address: ip };
                                    let sql_log = "INSERT INTO tbl_customer_log SET ?";
                                    conn.query(sql_log, post_log)

                                    //create tbl_ledger_master
                                    var post4 = { account_id: account_id, partner_key: partner_key, ledger_master_amount: 0, ledger_master_point: 0, ledger_master_date: created_date };
                                    let sql4 = "INSERT INTO tbl_ledger_master SET ?";
                                    conn.query(sql4, post4)

                                    //create tbl_ledger
                                    var post5 = { ledger_type: 'CREDIT', created_date: created_date, ledger_method: 'INITIAL', ledger_trx_status: 'SUKSES', ledger_amount: 0, ledger_point: 0, account_id: account_id, sn_client: account_id, sn_trx: account_id, ledger_description: 'New Registration', partner_key: partner_key, handset_type: handset_type, ip_address: ip };
                                    let sql5 = "INSERT INTO tbl_ledger SET ?";
                                    conn.query(sql5, post5)

                                    //delete this data from tbl_otp
                                    let sql6 = "DELETE FROM tbl_otp WHERE account_id = ? LIMIT 1";
                                    conn.query(sql6, [account_id]);

                                    res.end(JSON.stringify({ "status": 200, "message": "OK" }))
                                }
                            });
                        }

                    });
                }
            }
        });
    }
});

app.post('/login', (req, res) => {
    /*
    parameter need:
    - partner_key               : You must post partner_key given by us on first time registration
    - customer_phone            : customer phone number
    - token                     : Combination of hash(256) -> DDMMYYYY + partner_key + partner_secret + app_id
    - pin                       : 6 digit customer pin

    if OK, we will send:
    - message code              : it is 200
    */

    const app_id = 'xxx';
    const partner_key = sanitizer.sanitize(req.body.partner_key);
    const customer_phone_number = sanitizer.sanitize(req.body.customer_phone_number);
    const pin = sanitizer.sanitize(req.body.pin);
    const mytoken = sanitizer.sanitize(req.body.token);
    const fcm_id = sanitizer.sanitize(req.body.fcm_id);
    const ip = req.clientIp.split(":").pop();
    const handset_type = sanitizer.sanitize(req.body.handset_type);

    //check if parameter is empty
    if (app_id == null || partner_key == null || customer_phone_number == null || mytoken == null || pin == null || app_id == '' || partner_key == '' || customer_phone_number == '' || mytoken == '' || pin == '') {
        res.end(JSON.stringify({ "status": 101, "message": "Parameter kosong seperti hati aku yang hampa" }));
    } else {

        /* 23-05-2020
        penambahan check jika user inputnya 0, maka diganti dengan 62, sebaliknya tetap input as is
        */
        let phone_number = '';
        let customer_phone_number2 = customer_phone_number.replace('+', '')
        if (customer_phone_number2.substring(1, 0) == 0) {
            phone_number = 62 + customer_phone_number2.substring(1, 20);
        } else {
            phone_number = customer_phone_number2;
        }

        //check data partner apakah benar di DB apa tidak
        conn.query("SELECT partner_id,partner_key, partner_secret FROM tbl_partner WHERE partner_key = ? LIMIT 1", [partner_key], function (error, results, fields) {
            if (results.length == 0) {
                res.end(JSON.stringify({ "status": 104, "message": 'Data Mitra tidak ditemukan' }));
            } else {
                var tanggal = moment().format('DDMMYYYY');
                let partner_secret = results[0].partner_secret;
                let partner_id = results[0].partner_id;
                let gabungan = tanggal + partner_key + partner_secret + app_id;
                const token = crypto.createHash('sha256').update(gabungan).digest('hex');

                if (token != mytoken) { //check apakah tokennya mismatch?
                    res.end(JSON.stringify({ "status": 102, "message": 'Token anda tidak berjodoh dengan token dari kami' }));
                } else {
                    //check apakah ID customer ada di DB apa tidak
                    conn.query("SELECT account_id, customer_phone_number, login_status, customer_pin FROM tbl_customer WHERE customer_phone_number = ? AND partner_key = ? LIMIT 1", [phone_number, partner_key], function (error, results, fields) {
                        if (results.length == 0) {
                            res.end(JSON.stringify({ "status": 103, "message": 'So sad...data anda tidak terdaftar...' }));
                        } else {
                            let account_id = results[0].account_id;
                            let login_status = results[0].login_status;
                            let pin_from_db = results[0].customer_pin;
                            if (login_status == 1) {
                                res.end(JSON.stringify({ "status": 103, "message": 'Oops...nomor ini sedang login' }));
                            } else {
                                if (pin_from_db != pin) {
                                    res.end(JSON.stringify({ "status": 119, "message": "So sad...kode pin tidak sama dengan data kami..." }));
                                } else {
                                    //update login_status = 1
                                    let sql = "UPDATE tbl_customer SET login_status = 0, fcm_id = ? WHERE account_id = ? LIMIT 1";
                                    conn.query(sql, [fcm_id, account_id]);

                                    //insert tbl_customer_log
                                    let created_date = moment.utc().format('YYYY-MM-DD HH:mm:ss');
                                    let post2 = { account_id: account_id, customer_phone_number: phone_number, customer_log_action: 'LOGIN', created_date: created_date, partner_key: partner_key, handset_type: handset_type, ip_address: ip };
                                    let sql2 = "INSERT INTO tbl_customer_log SET ?";
                                    conn.query(sql2, [post2]);
                                    res.end(JSON.stringify({ "status": 200, "message": "OK", "account_id": account_id }))
                                }
                            }
                        }
                    });
                }
            }
        });
    }
});

app.post('/topup', (req, res) => {
    /*
    parameter need:
    - partner_key               : You must post partner_key given by us on first time registration
    - amount                    : amount for topup. Input number only
    - customer_phone_number     : customer_phone_number
    - token                     : Combination of hash(256) -> DDMMYYYY + partner_key + partner_secret + app_id
    - merchant_code             : code merchant that where is the payment came from (OVO, LinkAJA, Bank Mandiri, Indomaret, etc)
    - payment_channel           : detail of payment service (ATM, IBANKING, ALFAMART CAB. SURABAYA, etc)
    - sn_client                 : random id sent from hitter. Consists of numeric and alphabet, 10 digits

    if OK, we will send:
    - message code              : it is 200
    - amount                   : amount for topup
    - customer_phone_number     : customer_phone_number
    - customer_balance          : latest customer balance after topup
    - sn_client                 : random id sent from hitter. We will send it back as is
    - sn_trx                    : random digit from us. Hitter must keep it just in case customer complaint, or use for reversal
    */
    const app_id = 'xxx';
    const ip = req.clientIp.split(":").pop();
    const partner_key = sanitizer.sanitize(req.body.partner_key);
    const pg = sanitizer.sanitize(req.body.pg);
    const amount = sanitizer.sanitize(req.body.amount);
    const customer_phone_number = sanitizer.sanitize(req.body.customer_phone_number);
    const mytoken = sanitizer.sanitize(req.body.token);
    const payment_channel = sanitizer.sanitize(req.body.merchant_code);
    const payment_method = sanitizer.sanitize(req.body.payment_channel);
    const sn_client = sanitizer.sanitize(req.body.sn_client);
    const handset_type = sanitizer.sanitize(req.body.handset_type);

    if (mytoken == null || partner_key == null || amount == null || customer_phone_number == null || merchant_code == null || payment_channel == null || sn_client == null || handset_type == null || pg == null || mytoken == '' || partner_key == '' || amount == '' || customer_phone_number == '' || merchant_code == '' || payment_channel == '' || sn_client == '' || handset_type == '' || pg == '') {
        res.end(JSON.stringify({ "status": 101, "message": 'Parameter kosong seperti hati aku yang hampa' }));
    } else {
        /* 23-05-2020
        penambahan check jika user inputnya 0, maka diganti dengan 62, sebaliknya tetap input as is
        */
        let phone_number = '';
        let customer_phone_number2 = customer_phone_number.replace('+', '')
        if (customer_phone_number2.substring(1, 0) == 0) {
            phone_number = 62 + customer_phone_number2.substring(1, 20);
        } else {
            phone_number = customer_phone_number2;
        }
        if (isNaN(amount)) {
            res.end(JSON.stringify({ "status": 105, "message": 'Angka harusnya berupa angka...' }));
        } else {
            //check data partner apakah benar di DB apa tidak
            conn.query("SELECT partner_id,partner_key, partner_secret FROM tbl_partner WHERE partner_key = ? LIMIT 1", [partner_key], function (error, results, fields) {
                if (results.length == 0) {
                    res.end(JSON.stringify({ "status": 104, "message": 'Data Mitra tidak ditemukan' }));
                } else {
                    var tanggal = moment().format('DDMMYYYY');
                    let partner_secret = results[0].partner_secret;
                    let partner_id = results[0].partner_id;
                    let gabungan = tanggal + partner_key + partner_secret + app_id;
                    const token = crypto.createHash('sha256').update(gabungan).digest('hex');

                    if (token != mytoken) {
                        res.end(JSON.stringify({ "status": 102, "message": 'Token anda tidak berjodoh dengan token dari kami' }));
                    } else {
                        //check apakah ID customer ada di DB apa tidak
                        let sql = "select account_id,partner_key FROM tbl_customer WHERE customer_phone_number = ? AND partner_key = ? LIMIT 1";
                        conn.query(sql, [phone_number, partner_key], (err, results) => {
                            if (results.length == 0) {
                                res.end(JSON.stringify({ "status": 103, "message": 'Oops...nomor telepon ini belum terdaftar' }));
                            } else {
                                let account_id = results[0].account_id;
                                //check sn_client sudah pernah dipakai/ada di DB apa tidak
                                let sql2 = "select sn_client from tbl_ledger where sn_client = ? LIMIT 1";
                                conn.query(sql2, [sn_client], (err, results) => {
                                    if (err) throw err;
                                    if (results.length > 0) {
                                        res.end(JSON.stringify({ "status": 106, "message": 'SN CLIENT sudah ada di data kami pak boss...pakai digit yang lain ya' }));
                                    } else {
                                        //insert ke tbl_trx
                                        let sn_trx = partner_id + "" + uniqid();
                                        let created_date = moment.utc().format('YYYY-MM-DD HH:mm:ss');

                                        //insert tbl_ledger
                                        var post5 = { ledger_type: 'CREDIT', created_date: created_date, ledger_method: 'TOPUP', ledger_trx_status: 'SUKSES', ledger_amount: amount, account_id: account_id, sn_client: sn_client, sn_trx: sn_trx, ip_address: ip, ledger_description: 'Add new deposit', partner_key: partner_key, payment_channel: payment_channel, payment_method: payment_method, payment_pg: pg, handset_type: handset_type, ip_address: ip };
                                        let sql5 = "INSERT INTO tbl_ledger SET ?";
                                        conn.query(sql5, post5)

                                        //update ledger master
                                        let sql3 = "UPDATE tbl_ledger_master SET ledger_master_amount = ledger_master_amount + ? WHERE account_id = ? LIMIT 1";
                                        conn.query(sql3, [amount, account_id])

                                        //input ke customer log
                                        var post_log = { account_id: account_id, customer_phone_number: phone_number, customer_log_action: 'TOPUP', created_date: created_date, partner_key: partner_key, handset_type: handset_type, ip_address: ip };
                                        let sql_log = "INSERT INTO tbl_customer_log SET ?";
                                        conn.query(sql_log, post_log)

                                        //retrieve customer balance from ledger master
                                        let sql4 = "SELECT ledger_master_amount FROM tbl_ledger_master WHERE account_id = ? LIMIT 1";
                                        conn.query(sql4, [account_id], function (err, results, fields) {
                                            if (err) throw err;
                                            let customer_balance = results[0].ledger_master_amount;
                                            res.end(JSON.stringify({ "status": 200, "message": 'OK', "account_id": account_id, "balance": customer_balance, "AMOUNT": amount, "sn_client": sn_client, "sn_trx": sn_trx }));
                                        });
                                    }
                                });
                            }
                        });
                    }
                }
            });
        }
    }
});

app.post('/balance', (req, res) => {
    /*
    parameter need:
    - partner_key           : You must post partner_key given by us on first time registration
    - token                 : Combination of hash(256) -> DDMMYYYY + partner_key + partner_secret + app_id
    - customer_phone_number : customer_phone_number to check balance
    */
    const app_id = 'xxx';
    const partner_key = sanitizer.sanitize(req.body.partner_key);
    const mytoken = sanitizer.sanitize(req.body.token);
    const customer_phone_number = sanitizer.sanitize(req.body.customer_phone_number);
    const ip = req.clientIp.split(":").pop();
    const handset_type = sanitizer.sanitize(req.body.handset_type);

    if (partner_key == null || customer_phone_number == null || mytoken == null || partner_key == '' || customer_phone_number == '' || mytoken == '') {
        res.end(JSON.stringify({ "status": 101, "message": 'Parameter kosong seperti hati aku yang hampa' }));
    } else {
        /* 23-05-2020
        penambahan check jika user inputnya 0, maka diganti dengan 62, sebaliknya tetap input as is
        */
        let phone_number = '';
        let customer_phone_number2 = customer_phone_number.replace('+', '')
        if (customer_phone_number2.substring(1, 0) == 0) {
            phone_number = 62 + customer_phone_number2.substring(1, 20);
        } else {
            phone_number = customer_phone_number2;
        }
        let sql = "SELECT partner_key, partner_secret FROM tbl_partner WHERE partner_key = ? LIMIT 1";
        conn.query(sql, [partner_key], function (error, results, fields) {
            var tanggal = moment().format('DDMMYYYY');
            let partner_secret = results[0].partner_secret;
            let gabungan = tanggal + partner_key + partner_secret + app_id;
            const token = crypto.createHash('sha256').update(gabungan).digest('hex');
            if (token != mytoken) {
                res.end(JSON.stringify({ "status": 102, "message": 'Token anda tidak berjodoh dengan token dari kami' }));
            } else {
                let sql_check = "SELECT account_id, customer_phone_number FROM tbl_customer WHERE customer_phone_number = ? AND partner_key = ? LIMIT 1";
                conn.query(sql_check, [phone_number, partner_key], (err, results, fields) => {
                    if (results.length == 0) {
                        res.end(JSON.stringify({ "status": 103, "message": 'Sepertinya nomor telepon ini tidak ada pada list kami...' }));
                    } else {
                        let account_id = results[0].account_id;
                        let sql = "SELECT ledger_master_amount FROM tbl_ledger_master WHERE account_id = ? LIMIT 1";
                        conn.query(sql, [account_id], (err, results, fields) => {
                            let customer_balance = results[0].ledger_master_amount;

                            //input ke customer log
                            let created_date = moment.utc().format('YYYY-MM-DD HH:mm:ss');
                            var post_log = { account_id: account_id, customer_phone_number: phone_number, customer_log_action: 'BALANCE', created_date: created_date, partner_key: partner_key, handset_type: handset_type, ip_address: ip };
                            let sql_log = "INSERT INTO tbl_customer_log SET ?";
                            conn.query(sql_log, post_log)

                            res.end(JSON.stringify({ "status": 200, "message": 'OK', "account_id": account_id, "balance": customer_balance }));
                        });
                    }
                });
            }
        });
        conn.escape(sql);
        mysql.escape(sql);
    }
});

app.post('/rvsl', (req, res) => {
    /*
    parameter need:
    - partner_key               : You must post partner_key given by us on first time registration
    - customer_phone_number     : customer_phone_number
    - token                     : Combination of hash(256) -> DDMMYYYY + partner_key + partner_secret + app_id
    - sn_client                 : sn_client that used when topup for this transaction which want to reversal
    - sn_trx                    : sn_trx that appears when topup which want to reversal has been succeed

    if OK, we will send:
    - message code             : it is 200
    - customer_phone_number    : customer_phone_number
    - message                  : will be stated as OK
    */
    const app_id = 'xxx';
    const partner_key = sanitizer.sanitize(req.body.partner_key);
    const customer_phone_number = sanitizer.sanitize(req.body.customer_phone_number);
    const mytoken = sanitizer.sanitize(req.body.token);
    const sn_client = sanitizer.sanitize(req.body.sn_client);
    const sn_trx = sanitizer.sanitize(req.body.sn_trx);
    const ip = req.clientIp.split(":").pop();
    const handset_type = sanitizer.sanitize(req.body.handset_type);

    if (mytoken == null || partner_key == null || customer_phone_number == null || sn_client == null || sn_trx == null || mytoken == '' || partner_key == '' || customer_phone_number == '' || sn_client == '' || sn_trx == '') {
        res.end(JSON.stringify({ "status": 101, "message": 'Parameter kosong seperti hati aku yang hampa' }));
    } else {
        /* 23-05-2020
        penambahan check jika user inputnya 0, maka diganti dengan 62, sebaliknya tetap input as is
        */
        let phone_number = '';
        let customer_phone_number2 = customer_phone_number.replace('+', '')
        if (customer_phone_number2.substring(1, 0) == 0) {
            phone_number = 62 + customer_phone_number2.substring(1, 20);
        } else {
            phone_number = customer_phone_number2;
        }
        //check data partner apakah benar di DB apa tidak
        conn.query("SELECT partner_id,partner_key, partner_secret FROM tbl_partner WHERE partner_key = ? LIMIT 1", [partner_key], function (error, results, fields) {
            if (results.length == 0) {
                res.end(JSON.stringify({ "status": 104, "message": 'Data Mitra tidak ditemukan' }));
            } else {
                var tanggal = moment().format('DDMMYYYY');
                let partner_secret = results[0].partner_secret;
                let partner_id = results[0].partner_id;
                let gabungan = tanggal + partner_key + partner_secret + app_id;
                const token = crypto.createHash('sha256').update(gabungan).digest('hex');

                if (token != mytoken) {
                    res.end(JSON.stringify({ "status": 102, "message": 'Token anda tidak berjodoh dengan token dari kami' }));
                } else {
                    //check apakah ID customer ada di DB apa tidak
                    let sql = "select account_id FROM tbl_customer WHERE customer_phone_number = ? AND partner_key = ? LIMIT 1";
                    conn.query(sql, [phone_number, partner_key], (err, results) => {
                        if (results.length == 0) {
                            res.end(JSON.stringify({ "status": 103, "message": 'So sad...nomor telepon ini tidak terdaftar di data kami...' }));
                        } else {
                            let account_id = results[0].account_id;
                            //check sn_client dan sn_trx ada di DB apa tidak
                            let sql2 = "select ledger_amount, sn_client, sn_trx from tbl_ledger where sn_client = ? AND sn_trx = ? AND reversal_status = 0 AND partner_key = ? LIMIT 1";
                            conn.query(sql2, [sn_client, sn_trx, partner_key], (err, results) => {
                                if (err) throw err;
                                if (results.length == 0) {
                                    res.end(JSON.stringify({ "status": 107, "message": 'Transaksi ini invalid lho' }));
                                } else {
                                    //insert ke tbl_trx
                                    let reversal_amount = results[0].ledger_amount;
                                    let new_sn_client = partner_key + uniqid();
                                    let created_date = moment.utc().format('YYYY-MM-DD HH:mm:ss');

                                    //update tbl_ledger yang di reversal
                                    let sql_rvsl = "UPDATE tbl_ledger SET reversal_status = ? WHERE sn_client = ? AND sn_trx = ? LIMIT 1";
                                    conn.query(sql_rvsl, [1, sn_client, sn_trx])

                                    //insert tbl_ledger
                                    var post5 = { ledger_type: 'DEBET', created_date: created_date, ledger_method: 'REVERSAL', ledger_amount: reversal_amount, account_id: account_id, sn_client: new_sn_client, sn_trx: sn_trx, ledger_description: 'Reversal', partner_key: partner_key, ip_address: ip, reversal_status: 1 };
                                    let sql5 = "INSERT INTO tbl_ledger SET ?";
                                    conn.query(sql5, post5)

                                    //update ledger master
                                    let sql3 = "UPDATE tbl_ledger_master SET ledger_master_amount = ledger_master_amount - ? WHERE account_id = ? LIMIT 1";
                                    conn.query(sql3, [reversal_amount, account_id])

                                    //retrieve customer balance from ledger master
                                    let sql4 = "SELECT ledger_master_amount FROM tbl_ledger_master WHERE account_id = ? LIMIT 1";
                                    conn.query(sql4, [account_id], function (err, results, fields) {
                                        if (err) throw err;
                                        let customer_balance = results[0].ledger_master_amount;

                                        //input ke customer log
                                        var post_log = { account_id: account_id, customer_phone_number: phone_number, customer_log_action: 'REVERSAL', created_date: created_date, partner_key: partner_key, handset_type: handset_type, ip_address: ip };
                                        let sql_log = "INSERT INTO tbl_customer_log SET ?";
                                        conn.query(sql_log, post_log)

                                        res.end(JSON.stringify({ "status": 200, "message": 'OK', "account_id": account_id, "balance": customer_balance, "new_sn_client": new_sn_client, "sn_trx": sn_trx }));
                                    });
                                }
                            });

                        }
                    });
                }
            }
        });
    }
});

app.post('/purchase', (req, res) => {
    /*
    parameter need:
    - partner_key               : You must post partner_key given by us on first time registration
    - customer_phone_number     : customer_phone_number
    - token                     : Combination of hash(256) -> DDMMYYYY + partner_key + partner_secret + app_id
    - amount                    : amount to deduct from his/her wallet
    - category                  : a service name use to deduct (ride, food, buy a magazine, pay a massage, etc)
    - sn_client                 : sn_client that used when topup for this transaction which want to reversal

    if OK, we will send:
    - message code              : it is 200
    - customer_phone_number     : customer_phone_number
    - customer_balance          : latest customer balance after deduction
    - sn_trx                    : random digit from us. Hitter must keep it just in case customer complaint, or use for reversal
    */
    const app_id = 'xxx';
    const partner_key = sanitizer.sanitize(req.body.partner_key);
    const customer_phone_number = sanitizer.sanitize(req.body.customer_phone_number);
    const mytoken = sanitizer.sanitize(req.body.token);
    const amount = sanitizer.sanitize(req.body.amount);
    const product_type = sanitizer.sanitize(req.body.product_type);
    const product_code = sanitizer.sanitize(req.body.product_code);
    const pin = sanitizer.sanitize(req.body.pin);
    const sn_client = sanitizer.sanitize(req.body.sn_client);
    const handset_type = sanitizer.sanitize(req.body.handset_type);
    const payment_method = sanitizer.sanitize(req.body.payment_channel);
    const pg = sanitizer.sanitize(req.body.pg);
    const ip = req.clientIp.split(":").pop();

    if (mytoken == null || partner_key == null || customer_phone_number == null || sn_client == null || amount == null || product_type == null || product_code == null || pin == null || mytoken == '' || partner_key == '' || customer_phone_number == '' || sn_client == '' || amount == '' || product_type == '' || product_code == '' || pin == '') {
        res.end(JSON.stringify({ "status": 101, "message": 'Parameter kosong seperti hati aku yang hampa' }));
    } else {
        /* 23-05-2020
        penambahan check jika user inputnya 0, maka diganti dengan 62, sebaliknya tetap input as is
        */
        let phone_number = '';
        let customer_phone_number2 = customer_phone_number.replace('+', '')
        if (customer_phone_number2.substring(1, 0) == 0) {
            phone_number = 62 + customer_phone_number2.substring(1, 20);
        } else {
            phone_number = customer_phone_number2;
        }
        //check data partner apakah benar di DB apa tidak
        conn.query("SELECT partner_id,partner_key, partner_secret FROM tbl_partner WHERE partner_key = ? LIMIT 1", [partner_key], function (error, results, fields) {
            if (results.length == 0) {
                res.end(JSON.stringify({ "status": 104, "message": 'Data Mitra tidak ditemukan' }));
            } else {
                var tanggal = moment().format('DDMMYYYY');
                let partner_secret = results[0].partner_secret;
                let partner_id = results[0].partner_id;
                let gabungan = tanggal + partner_key + partner_secret + app_id;
                const token = crypto.createHash('sha256').update(gabungan).digest('hex');

                if (token != mytoken) {
                    res.end(JSON.stringify({ "status": 102, "message": 'Token anda tidak berjodoh dengan token dari kami' }));
                } else {
                    //check apakah product code ada di DB nggak
                    let sql = "select product_code FROM tbl_product WHERE product_code = ? LIMIT 1";
                    conn.query(sql, [product_code], (err, results) => {
                        if (results.length == 0) {
                            res.end(JSON.stringify({ "status": 103, "message": 'Kode produk tidak tersedia' }));
                        } else {
                            //check apakah ID customer ada di DB apa tidak
                            let sql = "select account_id, customer_phone_number, customer_pin FROM tbl_customer WHERE customer_phone_number = ? AND customer_pin = ? AND partner_key = ? LIMIT 1";
                            conn.query(sql, [phone_number, pin, partner_key], (err, results) => {
                                if (results.length == 0) {
                                    res.end(JSON.stringify({ "status": 103, "message": 'So sad...nomor telepon atau pin anda salah...' }));
                                } else {
                                    //check data dia di ledger ada nggak
                                    let account_id = results[0].account_id;
                                    let sql2 = "SELECT ledger_master_amount FROM tbl_ledger_master WHERE account_id  = ? LIMIT 1";
                                    conn.query(sql2, [account_id], (err, r_ledger) => {
                                        if (err) throw err;
                                        if (results.length == 0) {
                                            res.end(JSON.stringify({ "status": 103, "message": 'So sad...nomor telepon ini tidak terdaftar di data kami...' }));
                                        } else {
                                            let ledger_master_amount = r_ledger[0].ledger_master_amount;
                                            //check sn_client di tbl_ledger duplikat nggak
                                            let sql2 = "SELECT sn_client FROM tbl_ledger WHERE sn_client  = ? LIMIT 1";
                                            conn.query(sql2, [sn_client], (err, results) => {
                                                if (err) throw err;
                                                if (results.length > 0) {
                                                    res.end(JSON.stringify({ "status": 106, "message": 'DUPLICATE SN CLIENT' }));
                                                } else {
                                                    //cek harga compare sama saldo nya
                                                    if (ledger_master_amount < amount || ledger_master_amount < 1) {
                                                        res.end(JSON.stringify({ "status": 108, "message": 'INSUFFICIENT AMOUNT' }));
                                                    } else {
                                                        let sn_trx = partner_id + "" + uniqid();
                                                        let created_date = moment.utc().format('YYYY-MM-DD HH:mm:ss');

                                                        //insert tbl_ledger
                                                        var post5 = { ledger_type: 'DEBET', created_date: created_date, ledger_description: 'Transaksi atas ' + product_type + ' dengan kode produk ' + product_code, ledger_amount: amount, account_id: account_id, ledger_trx_status: 'SUKSES', sn_client: sn_client, sn_trx: sn_trx, ledger_method: 'PURCHASE', partner_key: partner_key, product_code: product_code, product_type: product_type, payment_method: payment_method, payment_pg: pg, handset_type: handset_type, ip_address: ip, ledger_source: 'WALLET' };
                                                        let sql5 = "INSERT INTO tbl_ledger SET ?";
                                                        conn.query(sql5, post5)

                                                        //update tbl_ledger_master
                                                        let last_balance = ledger_master_amount - amount;
                                                        let sql3 = "UPDATE tbl_ledger_master SET ledger_master_amount = ?, ledger_master_date = ? where account_id = ? LIMIT 1";
                                                        conn.query(sql3, [last_balance, created_date, account_id])

                                                        //input ke customer log
                                                        var post_log = { account_id: account_id, customer_phone_number: phone_number, customer_log_action: 'PURCHASE', created_date: created_date, partner_key: partner_key, handset_type: handset_type, ip_address: ip };
                                                        let sql_log = "INSERT INTO tbl_customer_log SET ?";
                                                        conn.query(sql_log, post_log)

                                                        res.end(JSON.stringify({ "status": 200, "message": 'OK', "account_id": account_id, "balance": last_balance, "sn_client": sn_client, "sn_trx": sn_trx }));
                                                    }
                                                }
                                            });
                                        }
                                    });

                                }
                            });
                        }
                    });
                }
            }
        });
    }
});

app.post('/viewProfile', (req, res) => {
    /*
    parameter need:
    - partner_key               : You must post partner_key given by us on first time registration
    - customer_phone_number     : customer_phone_number
    - token                     : Combination of hash(256) -> DDMMYYYY + partner_key + partner_secret + app_id

    if OK, we will send:
    - message code              : it is 200
    - customer_phone_number     : customer_phone_number
    - customer_balance          : latest customer balance after deduction
    - customer_name             : customer name
    - customer email            : customer email address
    */
    const app_id = 'xxx';
    const partner_key = sanitizer.sanitize(req.body.partner_key);
    const customer_phone_number = sanitizer.sanitize(req.body.customer_phone_number);
    const mytoken = sanitizer.sanitize(req.body.token);
    const handset_type = sanitizer.sanitize(req.body.handset_type);
    const ip = req.clientIp.split(":").pop();

    if (mytoken == null || partner_key == null || customer_phone_number == null || mytoken == '' || partner_key == '' || customer_phone_number == '') {
        res.end(JSON.stringify({ "status": 101, "message": 'Parameter kosong seperti hati aku yang hampa' }));
    } else {
        /* 23-05-2020
        penambahan check jika user inputnya 0, maka diganti dengan 62, sebaliknya tetap input as is
        */
        let phone_number = '';
        let customer_phone_number2 = customer_phone_number.replace('+', '')
        if (customer_phone_number2.substring(1, 0) == 0) {
            phone_number = 62 + customer_phone_number2.substring(1, 20);
        } else {
            phone_number = customer_phone_number2;
        }
        //check data partner apakah benar di DB apa tidak
        conn.query("SELECT partner_id,partner_key, partner_secret FROM tbl_partner WHERE partner_key = ? LIMIT 1", [partner_key], function (error, results, fields) {
            if (results.length == 0) {
                res.end(JSON.stringify({ "status": 104, "message": 'Data Mitra tidak ditemukan' }));
            } else {
                var tanggal = moment().format('DDMMYYYY');
                let partner_secret = results[0].partner_secret;
                let partner_id = results[0].partner_id;
                let gabungan = tanggal + partner_key + partner_secret + app_id;
                const token = crypto.createHash('sha256').update(gabungan).digest('hex');

                if (token != mytoken) {
                    res.end(JSON.stringify({ "status": 102, "message": 'Token anda tidak berjodoh dengan token dari kami', 'a': token }));
                } else {
                    //check apakah ID customer ada di DB apa tidak
                    let sql = "select account_id, customer_phone_number, customer_name, customer_email_address FROM tbl_customer WHERE customer_phone_number = ? AND partner_key = ? LIMIT 1";
                    conn.query(sql, [phone_number, partner_key], (err, results) => {
                        if (results.length == 0) {
                            res.end(JSON.stringify({ "status": 103, "message": 'So sad...nomor telepon ini tidak terdaftar di data kami...' }));
                        } else {
                            //check data dia di ledger ada nggak
                            let customer_phone_number = results[0].customer_phone_number;
                            let customer_name = results[0].customer_name;
                            let customer_email_address = results[0].customer_email_address;
                            let account_id = results[0].account_id;
                            let sql2 = "SELECT ledger_master_amount FROM tbl_ledger_master WHERE account_id  = ? LIMIT 1";
                            conn.query(sql2, [account_id], (err, r_ledger) => {
                                if (err) throw err;
                                if (results.length == 0) {
                                    res.end(JSON.stringify({ "status": 103, "message": 'So sad...nomor telepon ini tidak terdaftar di data kami...' }));
                                } else {
                                    let ledger_master_amount = r_ledger[0].ledger_master_amount;
                                    res.end(JSON.stringify({ "status": 200, "message": 'OK', "account_id": account_id, "customer_phone_number": customer_phone_number, "customer_name": customer_name, "customer_email_address": customer_email_address, "balance": ledger_master_amount }));
                                }
                            });
                        }
                    });
                }
            }
        });
    }
});

app.post('/editProfile', (req, res) => {
    /*
    parameter need:
    - partner_key               : You must post partner_key given by us on first time registration
    - customer_phone_number     : customer_phone_number
    - pin                       : customer pin
    - customer_name             : customer name
    - customer email            : customer email address
    - token                     : Combination of hash(256) -> DDMMYYYY + partner_key + partner_secret + app_id

    if OK, we will send:
    - message code              : it is 200
    - customer_phone_number     : customer_phone_number
    - customer_balance          : latest customer balance after deduction
    - customer_name             : customer name
    - customer email            : customer email address
    */
    const app_id = 'xxx';
    const partner_key = sanitizer.sanitize(req.body.partner_key);
    const customer_phone_number = sanitizer.sanitize(req.body.customer_phone_number);
    const customer_name = sanitizer.sanitize(req.body.customer_name);
    const customer_email_address = sanitizer.sanitize(req.body.customer_email_address);
    const pin = sanitizer.sanitize(req.body.pin);
    const mytoken = sanitizer.sanitize(req.body.token);
    const handset_type = sanitizer.sanitize(req.body.handset_type);
    const ip = req.clientIp.split(":").pop();

    if (mytoken == null || partner_key == null || customer_phone_number == null || customer_name == null || customer_email_address == null || pin == null || mytoken == '' || partner_key == '' || customer_phone_number == '' || customer_name == '' || customer_email_address == '' || pin == '') {
        res.end(JSON.stringify({ "status": 101, "message": 'Parameter kosong seperti hati aku yang hampa' }));
    } else {
        /* 23-05-2020
        penambahan check jika user inputnya 0, maka diganti dengan 62, sebaliknya tetap input as is
        */
        let phone_number = '';
        let customer_phone_number2 = customer_phone_number.replace('+', '')
        if (customer_phone_number2.substring(1, 0) == 0) {
            phone_number = 62 + customer_phone_number2.substring(1, 20);
        } else {
            phone_number = customer_phone_number2;
        }
        //check data partner apakah benar di DB apa tidak
        conn.query("SELECT partner_id,partner_key, partner_secret FROM tbl_partner WHERE partner_key = ? LIMIT 1", [partner_key], function (error, results, fields) {
            if (results.length == 0) {
                res.end(JSON.stringify({ "status": 104, "message": 'Data Mitra tidak ditemukan' }));
            } else {
                var tanggal = moment().format('DDMMYYYY');
                let partner_secret = results[0].partner_secret;
                let partner_id = results[0].partner_id;
                let gabungan = tanggal + partner_key + partner_secret + app_id;
                const token = crypto.createHash('sha256').update(gabungan).digest('hex');

                if (token != mytoken) {
                    res.end(JSON.stringify({ "status": 102, "message": 'Token anda tidak berjodoh dengan token dari kami' }));
                } else {
                    //check apakah ID customer ada di DB apa tidak
                    let sql = "select account_id, customer_phone_number, customer_name, customer_email_address, customer_pin FROM tbl_customer WHERE customer_phone_number = ? AND customer_pin = ? LIMIT 1";
                    conn.query(sql, [phone_number, pin], (err, results) => {
                        if (results.length == 0) {
                            res.end(JSON.stringify({ "status": 103, "message": 'So sad...nomor telepon atau pin anda salah...' }));
                        } else {
                            let pin_from_db = results[0].customer_pin;
                            let account_id = results[0].account_id;
                            if (pin_from_db != pin) {
                                res.end(JSON.stringify({ "status": 119, "message": "So sad...kode pin tidak sama dengan data kami..." }));
                            } else {
                                //edit data dia
                                let sql2 = "UPDATE tbl_customer SET customer_name = ?, customer_email_address = ? WHERE customer_phone_number  = ? LIMIT 1";
                                conn.query(sql2, [customer_name, customer_email_address, phone_number]);
                                conn.query(sql2);
                                res.end(JSON.stringify({ "status": 200, "message": 'Yeayy, update profil sukses', "account_id": account_id, "customer_phone_number": phone_number, "customer_name": customer_name, "customer_email_address": customer_email_address }));
                            }
                        }
                    });
                }
            }
        });
    }
});

app.post('/transfer', (req, res) => {
    /*
    parameter need:
    - partner_key               : You must post partner_key given by us on first time registration
    - customer_phone_number     : customer_phone_number
    - token                     : Combination of hash(256) -> DDMMYYYY + partner_key + partner_secret + app_id
    - amount                    : amount to deduct from his/her wallet
    - target_phone_number       : customer_phone_number target who will receive money
    - sn_client                 : sn_client that used when topup for this transaction which want to reversal

    if OK, we will send:
    - message code              : it is 200
    - customer_phone_number     : customer_phone_number
    - customer_balance          : latest customer balance after deduction
    - target_phone_number       : customer_phone_number target who will receive money
    - target_balance            : latest target balance after receive money
    - sn_trx                    : random digit from us. Hitter must keep it just in case customer complaint, or use for reversal
    */
    const app_id = 'xxx';
    const partner_key = sanitizer.sanitize(req.body.partner_key);
    const customer_phone_number = sanitizer.sanitize(req.body.customer_phone_number);
    const mytoken = sanitizer.sanitize(req.body.token);
    const amount2 = sanitizer.sanitize(req.body.amount);
    const target_phone_number = sanitizer.sanitize(req.body.target_phone_number);
    const pin = sanitizer.sanitize(req.body.pin);
    const sn_client = sanitizer.sanitize(req.body.sn_client);
    const handset_type = sanitizer.sanitize(req.body.handset_type);
    const ip = req.clientIp.split(":").pop();
    let amount = parseInt(amount2, 10);


    if (mytoken == null || partner_key == null || customer_phone_number == null || sn_client == null || amount == null || target_phone_number == null || pin == null || mytoken == '' || partner_key == '' || customer_phone_number == '' || sn_client == '' || amount == '' || target_phone_number == '' || pin == '') {
        res.end(JSON.stringify({ "status": 101, "message": 'Parameter kosong seperti hati aku yang hampa' }));
    } else {
        /* 23-05-2020
        penambahan check jika user inputnya 0, maka diganti dengan 62, sebaliknya tetap input as is
        */
        let phone_number = '';
        let phone_number2 = '';
        let customer_phone_number2 = customer_phone_number.replace('+', '')
        let target_phone_number2 = target_phone_number.replace('+', '')

        if (customer_phone_number2.substring(1, 0) == 0) {
            phone_number = 62 + customer_phone_number2.substring(1, 20);
        } else {
            phone_number = customer_phone_number2;
        }

        if (target_phone_number2.substring(1, 0) == 0) {
            phone_number2 = 62 + target_phone_number2.substring(1, 20);
        } else {
            phone_number2 = target_phone_number2;
        }
        //check data partner apakah benar di DB apa tidak
        conn.query("SELECT partner_id,partner_key, partner_secret FROM tbl_partner WHERE partner_key = ? LIMIT 1", [partner_key], function (error, results, fields) {
            if (results.length == 0) {
                res.end(JSON.stringify({ "status": 104, "message": 'Data Mitra tidak ditemukan' }));
            } else {
                var tanggal = moment().format('DDMMYYYY');
                let partner_secret = results[0].partner_secret;
                let partner_id = results[0].partner_id;
                let gabungan = tanggal + partner_key + partner_secret + app_id;
                const token = crypto.createHash('sha256').update(gabungan).digest('hex');

                if (token != mytoken) {
                    res.end(JSON.stringify({ "status": 102, "message": 'Token anda tidak berjodoh dengan token dari kami', 'a': token }));
                } else {
                    //check apakah ID customer ada di DB apa tidak
                    let sql = "select account_id, customer_phone_number, customer_pin FROM tbl_customer WHERE customer_phone_number = ? AND customer_pin = ? AND partner_key = ? LIMIT 1";
                    conn.query(sql, [phone_number, pin, partner_key], (err, results) => {
                        if (results.length == 0) {
                            res.end(JSON.stringify({ "status": 103, "message": 'So sad...nomor telepon atau pin anda salah...' }));
                        } else {
                            let pin_from_db = results[0].customer_pin;
                            let account_id_sender = results[0].account_id;
                            if (pin_from_db != pin) {
                                res.end(JSON.stringify({ "status": 119, "message": "So sad...kode pin tidak sama dengan data kami..." }));
                            } else {
                                //check apakah target customer ada di DB apa tidak
                                let sql = "select account_id, customer_phone_number FROM tbl_customer WHERE customer_phone_number = ? AND partner_key = ? LIMIT 1";
                                conn.query(sql, [phone_number2, partner_key], (err, results) => {
                                    if (results.length == 0) {
                                        res.end(JSON.stringify({ "status": 103, "message": 'So sad...nomor telepon penerima tidak terdaftar di data kami...' }));
                                    } else {
                                        //check data pengirim di ledger ada nggak
                                        let account_id_receiver = results[0].account_id;
                                        let sql2 = "SELECT ledger_master_amount FROM tbl_ledger_master WHERE account_id  = ? LIMIT 1";
                                        conn.query(sql2, [account_id_sender], (err, r_ledger) => {
                                            if (err) throw err;
                                            if (results.length == 0) {
                                                res.end(JSON.stringify({ "status": 103, "message": 'So sad...data pengirim tidak terdaftar di data kami...' }));
                                            } else {
                                                let ledger_master_amount = r_ledger[0].ledger_master_amount;
                                                //check data penerima di ledger ada nggak
                                                let sql2 = "SELECT ledger_master_amount FROM tbl_ledger_master WHERE account_id  = ? LIMIT 1";
                                                conn.query(sql2, [account_id_receiver], (err, r_ledger_receiver) => {
                                                    if (err) throw err;
                                                    if (results.length == 0) {
                                                        res.end(JSON.stringify({ "status": 103, "message": 'So sad...data penerima tidak terdaftar di data kami...' }));
                                                    } else {
                                                        let ledger_master_amount_receiver = r_ledger_receiver[0].ledger_master_amount;
                                                        if (phone_number == phone_number2) {
                                                            res.end(JSON.stringify({ "status": 122, "message": 'Nomor pengirim dan penerima kok sama?' }));
                                                        } else {
                                                            //check sn_client di tbl_ledger duplikat nggak
                                                            let sql2 = "SELECT sn_client FROM tbl_ledger WHERE sn_client  = ? LIMIT 1";
                                                            conn.query(sql2, [sn_client], (err, results) => {
                                                                if (err) throw err;
                                                                if (results.length > 0) {
                                                                    res.end(JSON.stringify({ "status": 106, "message": 'SN Client telah ada di data kami. Ayo gunakan SN Client lainnya' }));
                                                                } else {
                                                                    //cek harga compare sama saldo nya
                                                                    if (ledger_master_amount < amount || ledger_master_amount < 1) {
                                                                        res.end(JSON.stringify({ "status": 108, "message": 'Uupss. Uang anda tidak cukup' }));
                                                                    } else {
                                                                        let sn_trx = partner_id + "" + uniqid();
                                                                        let sn_client_receiver = uniqid();
                                                                        let created_date = moment.utc().format('YYYY-MM-DD HH:mm:ss');

                                                                        //insert tbl_ledger si pengirim
                                                                        var post_sender = { ledger_type: 'DEBET', ledger_trx_status: 'SUKSES', created_date: created_date, ledger_description: 'Transfer balance ke ' + account_id_receiver, ledger_method: 'TRANSFER', ledger_amount: amount, account_id: account_id_sender, target_customer_id: account_id_receiver, sn_client: sn_client, sn_trx: account_id_receiver, partner_key: partner_key, handset_type: handset_type, ip_address: ip };
                                                                        let sql_sender = "INSERT INTO tbl_ledger SET ?";
                                                                        conn.query(sql_sender, post_sender)

                                                                        //insert tbl_ledger si penerima
                                                                        var post_receiver = { ledger_type: 'CREDIT', ledger_trx_status: 'SUKSES', created_date: created_date, ledger_description: 'Transfer balance dari ' + account_id_sender, ledger_method: 'TRANSFER', ledger_amount: amount, account_id: account_id_receiver, sn_client: sn_client, sn_trx: account_id_sender, partner_key: partner_key, handset_type: handset_type, ip_address: ip };
                                                                        let sql_receiver = "INSERT INTO tbl_ledger SET ?";
                                                                        conn.query(sql_receiver, post_receiver)

                                                                        //update tbl_ledger_master pengirim
                                                                        let last_balance_sender = ledger_master_amount - amount;
                                                                        let sql_sender_balance = "UPDATE tbl_ledger_master SET ledger_master_amount = ?, ledger_master_date = ? where account_id = ? LIMIT 1";
                                                                        conn.query(sql_sender_balance, [last_balance_sender, created_date, account_id_sender])

                                                                        //update tbl_ledger_master penerima
                                                                        let last_balance_receiver = ledger_master_amount_receiver + amount;
                                                                        let sql_receiver_balance = "UPDATE tbl_ledger_master SET ledger_master_amount = ?, ledger_master_date = ? where account_id = ? LIMIT 1";
                                                                        conn.query(sql_receiver_balance, [last_balance_receiver, created_date, account_id_receiver])

                                                                        //input ke customer log
                                                                        var post_log = { account_id: account_id_sender, customer_phone_number: phone_number, customer_log_action: 'TRANSFER', created_date: created_date, partner_key: partner_key, handset_type: handset_type, ip_address: ip };
                                                                        let sql_log = "INSERT INTO tbl_customer_log SET ?";
                                                                        conn.query(sql_log, post_log)

                                                                        res.end(JSON.stringify({ "status": 200, "message": 'OK', "account_id": account_id_sender, "sender_balance": last_balance_sender, "receiver_balance": last_balance_receiver, "amount": amount, "sn_client": sn_client, "sn_trx": sn_trx }));
                                                                    }
                                                                }
                                                            });
                                                        }
                                                    }
                                                });
                                            }
                                        });
                                    }
                                });
                            }

                        }
                    });
                }
            }
        });
    }
});


app.post('/buyCustomerProduct', (req, res) => {
    /*
    parameter need:
    - partner_key               : You must post partner_key given by us on first time registration
    - customer_phone_number     : customer_phone_number
    - token                     : Combination of hash(256) -> DDMMYYYY + partner_key + partner_secret + app_id
    - amount                    : amount to deduct from his/her wallet
    - target_phone_number       : customer_phone_number target who will receive money
    - sn_client                 : sn_client that used when topup for this transaction which want to reversal

    if OK, we will send:
    - message code              : it is 200
    - customer_phone_number     : customer_phone_number
    - customer_balance          : latest customer balance after deduction
    - target_phone_number       : customer_phone_number target who will receive money
    - target_balance            : latest target balance after receive money
    - sn_trx                    : random digit from us. Hitter must keep it just in case customer complaint, or use for reversal
    */
    const app_id = 'xxx';
    const partner_key = sanitizer.sanitize(req.body.partner_key);
    const customer_phone_number = sanitizer.sanitize(req.body.customer_phone_number);
    const mytoken = sanitizer.sanitize(req.body.token);
    const amount2 = sanitizer.sanitize(req.body.amount);
    const seller_phone_number = sanitizer.sanitize(req.body.seller_phone_number);
    const pin = sanitizer.sanitize(req.body.pin);
    const sn_client = sanitizer.sanitize(req.body.sn_client);
    const handset_type = sanitizer.sanitize(req.body.handset_type);
    const product_id = sanitizer.sanitize(req.body.product_id);
    const ip = req.clientIp.split(":").pop();
    let amount = parseInt(amount2, 10);
    const title = sanitizer.sanitize(req.body.title);
    const message_body = sanitizer.sanitize(req.body.message_body);
    const product_harga = amount;
    const product_deskripsi = sanitizer.sanitize(req.body.product_deskripsi);
    const product_nama = sanitizer.sanitize(req.body.product_nama);

    if (mytoken == null || partner_key == null || customer_phone_number == null || sn_client == null || amount == null || seller_phone_number == null || pin == null || product_id == null || mytoken == '' || partner_key == '' || customer_phone_number == '' || sn_client == '' || amount == '' || seller_phone_number == '' || pin == '' || product_id == '') {
        res.end(JSON.stringify({ "status": 101, "message": 'Parameter kosong seperti hati aku yang hampa' }));
    } else {
        /* 23-05-2020
        penambahan check jika user inputnya 0, maka diganti dengan 62, sebaliknya tetap input as is
        */
        let phone_number = '';
        let phone_number2 = '';
        let customer_phone_number2 = customer_phone_number.replace('+', '')
        let seller_phone_number2 = seller_phone_number.replace('+', '')

        if (customer_phone_number2.substring(1, 0) == 0) {
            phone_number = 62 + customer_phone_number2.substring(1, 20);
        } else {
            phone_number = customer_phone_number2;
        }

        if (seller_phone_number2.substring(1, 0) == 0) {
            phone_number2 = 62 + seller_phone_number2.substring(1, 20);
        } else {
            phone_number2 = seller_phone_number2;
        }
        //check data partner apakah benar di DB apa tidak
        conn.query("SELECT partner_id,partner_key, partner_secret FROM tbl_partner WHERE partner_key = ? LIMIT 1", [partner_key], function (error, results, fields) {
            if (results.length == 0) {
                res.end(JSON.stringify({ "status": 104, "message": 'Data Mitra tidak ditemukan' }));
            } else {
                var tanggal = moment().format('DDMMYYYY');
                let partner_secret = results[0].partner_secret;
                let partner_id = results[0].partner_id;
                let gabungan = tanggal + partner_key + partner_secret + app_id;
                const token = crypto.createHash('sha256').update(gabungan).digest('hex');

                if (token != mytoken) {
                    res.end(JSON.stringify({ "status": 102, "message": 'Token anda tidak berjodoh dengan token dari kami', 'a': token }));
                } else {
                    //check apakah ID customer ada di DB apa tidak
                    let sql = "select account_id, customer_phone_number, customer_pin FROM tbl_customer WHERE customer_phone_number = ? AND customer_pin = ? AND partner_key = ? LIMIT 1";
                    conn.query(sql, [phone_number, pin, partner_key], (err, results) => {
                        if (results.length == 0) {
                            res.end(JSON.stringify({ "status": 103, "message": 'So sad...nomor telepon atau pin anda salah...' }));
                        } else {
                            let pin_from_db = results[0].customer_pin;
                            let account_id_sender = results[0].account_id;
                            if (pin_from_db != pin) {
                                res.end(JSON.stringify({ "status": 119, "message": "So sad...kode pin tidak sama dengan data kami..." }));
                            } else {
                                //check apakah target customer ada di DB apa tidak
                                let sql = "select account_id, customer_phone_number FROM tbl_customer WHERE customer_phone_number = ? AND partner_key = ? LIMIT 1";
                                conn.query(sql, [phone_number2, partner_key], (err, results) => {
                                    if (results.length == 0) {
                                        res.end(JSON.stringify({ "status": 103, "message": 'So sad...nomor telepon penerima tidak terdaftar di data kami...' }));
                                    } else {
                                        //check data pengirim di ledger ada nggak
                                        let account_id_receiver = results[0].account_id;
                                        let sql2 = "SELECT ledger_master_amount FROM tbl_ledger_master WHERE account_id  = ? LIMIT 1";
                                        conn.query(sql2, [account_id_sender], (err, r_ledger) => {
                                            if (err) throw err;
                                            if (results.length == 0) {
                                                res.end(JSON.stringify({ "status": 103, "message": 'So sad...data pengirim tidak terdaftar di data kami...' }));
                                            } else {
                                                let ledger_master_amount = r_ledger[0].ledger_master_amount;
                                                //check data penerima di ledger ada nggak
                                                let sql2 = "SELECT ledger_master_amount FROM tbl_ledger_master WHERE account_id  = ? LIMIT 1";
                                                conn.query(sql2, [account_id_receiver], (err, r_ledger_receiver) => {
                                                    if (err) throw err;
                                                    if (results.length == 0) {
                                                        res.end(JSON.stringify({ "status": 103, "message": 'So sad...data penerima tidak terdaftar di data kami...' }));
                                                    } else {
                                                        let ledger_master_amount_receiver = r_ledger_receiver[0].ledger_master_amount;
                                                        if (phone_number == phone_number2) {
                                                            res.end(JSON.stringify({ "status": 122, "message": 'Nomor pengirim dan penerima kok sama?' }));
                                                        } else {
                                                            //check sn_client di tbl_ledger duplikat nggak
                                                            let sql2 = "SELECT sn_client FROM tbl_ledger WHERE sn_client  = ? LIMIT 1";
                                                            conn.query(sql2, [sn_client], (err, results) => {
                                                                if (err) throw err;
                                                                if (results.length > 0) {
                                                                    res.end(JSON.stringify({ "status": 106, "message": 'SN Client telah ada di data kami. Ayo gunakan SN Client lainnya' }));
                                                                } else {
                                                                    //cek harga compare sama saldo nya
                                                                    if (ledger_master_amount < amount || ledger_master_amount < 1) {
                                                                        res.end(JSON.stringify({ "status": 108, "message": 'Uupss. Uang anda tidak cukup' }));
                                                                    } else {
                                                                        let sn_trx = partner_id + "" + uniqid();
                                                                        let sn_client_receiver = uniqid();
                                                                        let created_date = moment.utc().format('YYYY-MM-DD HH:mm:ss');

                                                                        //get product name
                                                                        conn.query("SELECT product_customer_name, product_selling_price FROM tbl_product WHERE product_id = ? LIMIT 1", [product_id], (err, r_products) => {
                                                                            let product_name = r_products[0].product_customer_name;
                                                                            let product_selling_price = r_products[0].product_selling_price;

                                                                            //insert tbl_ledger si pengirim
                                                                            var post_sender = { ledger_type: 'DEBET', ledger_trx_status: 'SUKSES', created_date: created_date, ledger_description: 'Pembelian produk ' + product_name + ' dari ' + account_id_receiver, ledger_method: 'PURCHASE', ledger_amount: amount, account_id: account_id_sender, sn_client: sn_client, sn_trx: account_id_receiver, partner_key: partner_key, handset_type: handset_type, ip_address: ip };
                                                                            let sql_sender = "INSERT INTO tbl_ledger SET ?";
                                                                            conn.query(sql_sender, post_sender)

                                                                            //insert tbl_ledger si penerima
                                                                            var post_receiver = { ledger_type: 'CREDIT', ledger_trx_status: 'SUKSES', created_date: created_date, ledger_description: 'Penjualan produk ' + product_name + ' ke ' + account_id_sender, ledger_method: 'INVOICE', ledger_amount: amount, account_id: account_id_receiver, sn_client: sn_client, sn_trx: account_id_sender, partner_key: partner_key, handset_type: handset_type, ip_address: ip };
                                                                            let sql_receiver = "INSERT INTO tbl_ledger SET ?";
                                                                            conn.query(sql_receiver, post_receiver)

                                                                            //update tbl_ledger_master pengirim
                                                                            let last_balance_sender = ledger_master_amount - amount;
                                                                            let sql_sender_balance = "UPDATE tbl_ledger_master SET ledger_master_amount = ?, ledger_master_date = ? where account_id = ? LIMIT 1";
                                                                            conn.query(sql_sender_balance, [last_balance_sender, created_date, account_id_sender])

                                                                            //update tbl_ledger_master penerima
                                                                            let last_balance_receiver = ledger_master_amount_receiver + amount;
                                                                            let sql_receiver_balance = "UPDATE tbl_ledger_master SET ledger_master_amount = ?, ledger_master_date = ? where account_id = ? LIMIT 1";
                                                                            conn.query(sql_receiver_balance, [last_balance_receiver, created_date, account_id_receiver])

                                                                            //input ke table transaction customer
                                                                            var post_trx_cust = { account_id_seller: account_id_receiver, account_id_buyer: account_id_sender, product_id: product_id, product_customer_name: product_name, product_selling_price: product_selling_price, final_price: amount, created_date: created_date, partner_key: partner_key, handset_type: handset_type, ip_address: ip }
                                                                            let sql_trx_cust = "INSERT INTO tbl_customer_transaction SET ?";
                                                                            conn.query(sql_trx_cust, post_trx_cust)

                                                                            //input ke customer log
                                                                            var post_log = { account_id: account_id_sender, customer_phone_number: phone_number, customer_log_action: 'PURCHASE', created_date: created_date, partner_key: partner_key, handset_type: handset_type, ip_address: ip };
                                                                            let sql_log = "INSERT INTO tbl_customer_log SET ?";
                                                                            conn.query(sql_log, post_log)

                                                                            //send FCM API
                                                                            var dataPost = querystring.stringify({
                                                                                app_id: 'customerSendNotif',
                                                                                seller_phone_number: seller_phone_number,
                                                                                buyer_phone_number: customer_phone_number,
                                                                                product_harga: product_harga,
                                                                                product_deskripsi: product_deskripsi,
                                                                                product_nama: product_nama
                                                                            });

                                                                            var options = {
                                                                                host: "ipay.satukode.com",
                                                                                path: "/api/sendNotifPurchaseSuccess.php",
                                                                                method: 'POST',
                                                                                headers: {
                                                                                    'Content-Type': 'application/x-www-form-urlencoded',
                                                                                    'Content-Length': dataPost.length
                                                                                }
                                                                            };

                                                                            var req = http.request(options, function (response) {
                                                                                console.log(response.statusCode);
                                                                                console.log(response.statusMessage);
                                                                                console.log(response.headers);
                                                                            });

                                                                            req.write(dataPost);
                                                                            req.end();

                                                                            res.end(JSON.stringify({ "status": 200, "message": 'OK', "account_id": account_id_sender, "sender_balance": last_balance_sender, "receiver_balance": last_balance_receiver, "amount": amount, "sn_client": sn_client, "sn_trx": sn_trx }));
                                                                        });
                                                                    }
                                                                }
                                                            });
                                                        }
                                                    }
                                                });
                                            }
                                        });
                                    }
                                });
                            }

                        }
                    });
                }
            }
        });
    }
});

var httpsServer = https.createServer(options, app);

httpsServer.listen(3008);
// app.listen(3008, () => console.log('Suckerhead'));

/*
update 9 sept 2020:
line 446-447 ada ubah parameter merchant_code dan payment_channel
*/
