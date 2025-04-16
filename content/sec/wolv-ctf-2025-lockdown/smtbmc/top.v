
module top();

    reg [47:0] password;


    reg  [31:0] a1;
    reg  [31:0] b1;
    wire [31:0] c1;

    add _1_ (
        .a(a1),
        .b(b1),
        .c(c1),
        .password(password)
    );

    reg  [31:0] a2;
    reg  [31:0] b2;
    wire [31:0] c2;

    add _2_ (
        .a(a2),
        .b(b2),
        .c(c2),
        .password(password)
    );

    reg  [31:0] a3;
    reg  [31:0] b3;
    wire [31:0] c3;

    add _3_ (
        .a(a3),
        .b(b3),
        .c(c3),
        .password(password)
    );

    reg  [31:0] a4;
    reg  [31:0] b4;
    wire [31:0] c4;

    add _4_ (
        .a(a4),
        .b(b4),
        .c(c4),
        .password(password)
    );

    reg  [31:0] a5;
    reg  [31:0] b5;
    wire [31:0] c5;

    add _5_ (
        .a(a5),
        .b(b5),
        .c(c5),
        .password(password)
    );

    reg  [31:0] a6;
    reg  [31:0] b6;
    wire [31:0] c6;

    add _6_ (
        .a(a6),
        .b(b6),
        .c(c6),
        .password(password)
    );

    reg  [31:0] a7;
    reg  [31:0] b7;
    wire [31:0] c7;

    add _7_ (
        .a(a7),
        .b(b7),
        .c(c7),
        .password(password)
    );

    reg  [31:0] a8;
    reg  [31:0] b8;
    wire [31:0] c8;

    add _8_ (
        .a(a8),
        .b(b8),
        .c(c8),
        .password(password)
    );

    reg  [31:0] a9;
    reg  [31:0] b9;
    wire [31:0] c9;

    add _9_ (
        .a(a9),
        .b(b9),
        .c(c9),
        .password(password)
    );

    reg  [31:0] a10;
    reg  [31:0] b10;
    wire [31:0] c10;

    add _10_ (
        .a(a10),
        .b(b10),
        .c(c10),
        .password(password)
    );

    reg  [31:0] a11;
    reg  [31:0] b11;
    wire [31:0] c11;

    add _11_ (
        .a(a11),
        .b(b11),
        .c(c11),
        .password(password)
    );

    reg  [31:0] a12;
    reg  [31:0] b12;
    wire [31:0] c12;

    add _12_ (
        .a(a12),
        .b(b12),
        .c(c12),
        .password(password)
    );

    reg  [31:0] a13;
    reg  [31:0] b13;
    wire [31:0] c13;

    add _13_ (
        .a(a13),
        .b(b13),
        .c(c13),
        .password(password)
    );

    reg  [31:0] a14;
    reg  [31:0] b14;
    wire [31:0] c14;

    add _14_ (
        .a(a14),
        .b(b14),
        .c(c14),
        .password(password)
    );

    reg  [31:0] a15;
    reg  [31:0] b15;
    wire [31:0] c15;

    add _15_ (
        .a(a15),
        .b(b15),
        .c(c15),
        .password(password)
    );

    reg  [31:0] a16;
    reg  [31:0] b16;
    wire [31:0] c16;

    add _16_ (
        .a(a16),
        .b(b16),
        .c(c16),
        .password(password)
    );


    initial begin
        a1 = 4206234075;
        b1 = 3624760546;
        a2 = 3158718995;
        b2 = 2826188822;
        a3 = 462863615;
        b3 = 3721679905;
        a4 = 1127877203;
        b4 = 3996909021;
        a5 = 2293482475;
        b5 = 126665807;
        a6 = 820108501;
        b6 = 3771782894;
        a7 = 981791449;
        b7 = 3627419547;
        a8 = 3385955481;
        b8 = 3682337427;
        a9 = 1410293874;
        b9 = 3166914840;
        a10 = 1990649809;
        b10 = 3993428029;
        a11 = 3573658880;
        b11 = 1794539216;
        a12 = 2028501941;
        b12 = 2963079400;
        a13 = 3404482866;
        b13 = 1162945547;
        a14 = 1363585863;
        b14 = 2766704733;
        a15 = 1915943569;
        b15 = 1986484709;
        a16 = 450877614;
        b16 = 644717717;
        // if we do not set an initial value for password,
        // the tool will find a value such that the
        // cover statement below is SAT
    end

    always @(*) begin
        cover (
            c1 == (a1 + b1)
            && c2 == (a2 + b2)
            && c3 == (a3 + b3)
            && c4 == (a4 + b4)
            && c5 == (a5 + b5)
            && c6 == (a6 + b6)
            && c7 == (a7 + b7)
            && c8 == (a8 + b8)
            && c9 == (a9 + b9)
            && c10 == (a10 + b10)
            && c11 == (a11 + b11)
            && c12 == (a12 + b12)
            && c13 == (a13 + b13)
            && c14 == (a14 + b14)
            && c15 == (a15 + b15)
            && c16 == (a16 + b16)
        );
    end

endmodule
