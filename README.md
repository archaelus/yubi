# yubi

An Erlang Yubico YubiKey OTP verification service client library.

Written using the [Yubico Verification Service Client Library Guide](https://github.com/Yubico/yubikey-val/wiki/GettingStartedWritingClients).

## Build

    $ rebar3 compile

## Run

    $ rebar3 shell
    ===> Verifying dependencies...
    ===> Compiling yubi
    Erlang/OTP 18 [erts-7.3] [source] [64-bit] [smp:4:4] [async-threads:0] [hipe] [kernel-poll:false] [dtrace]
    
    Eshell V7.3  (abort with ^G)
    1> ===> The rebar3 shell is a development tool; to deploy applications in production, consider using releases (http://www.rebar3.org/v3.0/docs/releases)
    ===> Booted idna
    ===> Booted mimerl
    ===> Booted certifi
    ===> Booted ssl_verify_fun
    ===> Booted metrics
    ===> Booted hackney
    ===> Booted yubi
    1> 

## Use

    1 > CID = Your Client Id Here %% e.g. <<"1">>
    2 > SK = Your Yubico secret key in base64 encoded format
    3 > yubi:validate(yubi:test_prompt(), CID, base64:decode(SK)).
    OTP> cccccccbcjdifctrndncchkftchjlnbhvhtugdljibej
    valid
    4> 
