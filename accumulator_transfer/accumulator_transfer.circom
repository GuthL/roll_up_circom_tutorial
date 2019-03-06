include "./circuits/mimc.circom";
include "./circuits/eddsa_no_hash.circom";
include "./circuits/bitify.circom";
include "./circuits/escalarmulany.circom";
include "./circuits/escalarmulfix.circom";

template Main() {
    signal input current_state_x;
    signal input current_state_y;

    signal private input remainder_x;
    signal private input remainder_y;

    signal private input pubkey_x;
    signal private input pubkey_y;
    signal private input R8x;
    signal private input R8y;
    signal private input S;

    signal private input nonce_from;
    signal private input to_x;
    signal private input to_y;
    signal private input nonce_to;
    signal private input amount;

    signal private input token_balance_from;
    signal private input token_balance_to;
    signal private input token_type_from;
    signal private input token_type_to;

    signal output out_x;
    signal output out_y;

    var i;

    var BASE8 = [
        1777755212379993395577990677965571241715742912184938656739573121738514868268,
        2626589144620713026669568689430873010625803728049924121243784502389097019475
    ];

    var NONCE_MAX_VALUE = 100;
    
    // accounts existence check

    component token_type_from2bits = Num2Bits(1);
    token_type_from2bits.in <== token_type_from;

    component nonce_from2bits = Num2Bits(16);
    nonce_from2bits.in <== nonce_from;

    component token_type_to2bits = Num2Bits(1);
    token_type_to2bits.in <== token_type_to;

    component nonce_to2bits = Num2Bits(16);
    nonce_to2bits.in <== nonce_to;

    component token_balance_to2bits = Num2Bits(64);
    token_balance_to2bits.in <== nonce_to;

    component token_type_from_mulFix = EscalarMulFix(1, BASE8);
    for (i=0; i<1; i++) {
        token_type_from_mulFix.e[i] <== token_type_from2bits.out[i];
    }

    component nonce_from_mulFix = EscalarMulFix(16, BASE8);
    for (i=0; i<16; i++) {
        nonce_from_mulFix.e[i] <== nonce_from2bits.out[i];
    }

    component token_type_to_mulFix = EscalarMulFix(1, BASE8);
    for (i=0; i<1; i++) {
        token_type_to_mulFix.e[i] <== token_type_to2bits.out[i];
    }

    component nonce_to_mulFix = EscalarMulFix(16, BASE8);
    for (i=0; i<16; i++) {
        nonce_to_mulFix.e[i] <== nonce_to2bits.out[i];
    }

    component n2b = Num2Bits(64);
    n2b.in <== token_balance_from;
    component mulAny_from = EscalarMulAny(64);
    for (i=0; i<64; i++) {
        mulAny_from.e[i] <== n2b.out[i];
    }
    mulAny_from.p[0] <== pubkey_x;
    mulAny_from.p[1] <== pubkey_y;

    component n2c = Num2Bits(64);
    n2c.in <== token_balance_to;
    component mulAny_to = EscalarMulAny(64);
    for (i=0; i<64; i++) {
        mulAny_to.e[i] <== n2c.out[i];
    }
    mulAny_to.p[0] <== to_x;
    mulAny_to.p[1] <== to_y;

    component babyjubjub_add_1 = BabyAdd();
    babyjubjub_add_1.x1 <== token_type_from_mulFix.out[0];
    babyjubjub_add_1.y1 <== token_type_from_mulFix.out[1];

    babyjubjub_add_1.x2 <== token_type_to_mulFix.out[0];
    babyjubjub_add_1.y2 <== token_type_to_mulFix.out[1];

    component babyjubjub_add_2 = BabyAdd();
    babyjubjub_add_2.x1 <== nonce_from_mulFix.out[0];
    babyjubjub_add_2.y1 <== nonce_from_mulFix.out[1];

    babyjubjub_add_2.x2 <== nonce_to_mulFix.out[0];
    babyjubjub_add_2.y2 <== nonce_to_mulFix.out[1];

    component babyjubjub_add_3 = BabyAdd();
    babyjubjub_add_3.x1 <== babyjubjub_add_1.xout;
    babyjubjub_add_3.y1 <== babyjubjub_add_1.yout;

    babyjubjub_add_2.x2 <== babyjubjub_add_2.xout;
    babyjubjub_add_2.y2 <== babyjubjub_add_2.yout; 

    component babyjubjub_add_from_to = BabyAdd();
    babyjubjub_add_from_to.x1 <== mulAny_from.out[0];
    babyjubjub_add_from_to.y1 <== mulAny_from.out[1];

    babyjubjub_add_from_to.x2 <== mulAny_to.out[0];
    babyjubjub_add_from_to.y2 <== mulAny_to.out[1];

    component babyjubjub_add_4 = BabyAdd();
    babyjubjub_add_4.x1 <== babyjubjub_add_from_to.xout;
    babyjubjub_add_4.y1 <== babyjubjub_add_from_to.yout;

    babyjubjub_add_4.x2 <== babyjubjub_add_3.xout;
    babyjubjub_add_4.y2 <== babyjubjub_add_3.yout; 

    component babyjubjub_add_state = BabyAdd();
    babyjubjub_add_state.x1 <== babyjubjub_add_4.xout;
    babyjubjub_add_state.y1 <== babyjubjub_add_4.yout;

    babyjubjub_add_state.x2 <== remainder_x;
    babyjubjub_add_state.y2 <== remainder_y;

    current_state_x === babyjubjub_add_state.xout;
    current_state_y === babyjubjub_add_state.yout;

// authorization check
    component verifier = EdDSAMiMCVerifier();   
    verifier.enabled <== 1;
    verifier.Ax <== pubkey_x;
    verifier.Ay <== pubkey_y;
    verifier.R8x <== R8x
    verifier.R8y <== R8y
    verifier.S <== S;
    verifier.M <== token_balance_from;
    verifier.mulAny_x <== mulAny_from.out[0];
    verifier.mulAny_y <== mulAny_from.out[1];
    
    // balance checks
    var new_token_balance_from = token_balance_from-amount;
    var new_token_balance_to = token_balance_to+amount;

    new_token_balance_from <= token_balance_from;
    new_token_balance_to >= token_balance_to;

    nonce_from != NONCE_MAX_VALUE;
    token_type_from === token_type_to;

    // accounts updates

    component new_n2b = Num2Bits(64);
    new_n2b.in <== new_token_balance_from;
    component new_mulAny_from = EscalarMulAny(64);
    for (i=0; i<64; i++) {
        new_mulAny_from.e[i] <== new_n2b.out[i];
    }
    new_mulAny_from.p[0] <== pubkey_x;
    new_mulAny_from.p[1] <== pubkey_y;

    component new_n2c = Num2Bits(64);
    new_n2c.in <== new_token_balance_to;
    component new_mulAny_to = EscalarMulAny(64);
    for (i=0; i<64; i++) {
        new_mulAny_to.e[i] <== new_n2c.out[i];
    }
    new_mulAny_to.p[0] <== to_x;
    new_mulAny_to.p[1] <== to_y;

    component babyjubjub_add_nonce = BabyAdd();
    babyjubjub_add_nonce.x2 <== nonce_from_mulFix.out[0];
    babyjubjub_add_nonce.y2 <== nonce_from_mulFix.out[1];

    babyjubjub_add_nonce.x2 <== BASE8[0];
    babyjubjub_add_nonce.y2 <== BASE8[1]; 

    component new_babyjubjub_add_1 = BabyAdd();
    new_babyjubjub_add_1.x1 <== babyjubjub_add_1.xout;
    new_babyjubjub_add_1.y1 <== babyjubjub_add_1.yout;

    new_babyjubjub_add_1.x2 <== babyjubjub_add_nonce.xout;
    new_babyjubjub_add_1.y2 <== babyjubjub_add_nonce.yout; 

    component new_babyjubjub_add_2 = BabyAdd();
    new_babyjubjub_add_2.x1 <== new_babyjubjub_add_1.xout;
    new_babyjubjub_add_2.y1 <== new_babyjubjub_add_1.yout;

    new_babyjubjub_add_2.x2 <== nonce_to_mulFix.out[0];
    new_babyjubjub_add_2.y2 <== nonce_to_mulFix.out[1]; 

    component new_babyjubjub_add_3 = BabyAdd();
    new_babyjubjub_add_3.x1 <== new_babyjubjub_add_2.xout;
    new_babyjubjub_add_3.y1 <== new_babyjubjub_add_2.yout;

    new_babyjubjub_add_3.x2 <== new_mulAny_from.out[0];
    new_babyjubjub_add_3.y2 <== new_mulAny_from.out[1]; 

    component new_babyjubjub_add_from_to = BabyAdd();
    new_babyjubjub_add_from_to.x1 <== new_babyjubjub_add_3.xout;
    new_babyjubjub_add_from_to.y1 <== new_babyjubjub_add_3.yout;

    new_babyjubjub_add_from_to.x2 <== new_mulAny_to.out[0];
    new_babyjubjub_add_from_to.y2 <== new_mulAny_to.out[1];

    component new_babyjubjub_add_state = BabyAdd();
    new_babyjubjub_add_state.x1 <== new_babyjubjub_add_from_to.xout;
    new_babyjubjub_add_state.y1 <== new_babyjubjub_add_from_to.yout;

    new_babyjubjub_add_state.x2 <== remainder_x;
    new_babyjubjub_add_state.y2 <== remainder_y;
    
    out_x <== new_babyjubjub_add_state.xout;
    out_y <== new_babyjubjub_add_state.yout;

    }

component main = Main();