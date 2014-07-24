yubi
=====

An Erlang Yubico YubiKey OTP verification service client library.

Written using the [Yubico Verification Service Client Library Guide](https://github.com/Yubico/yubikey-val/wiki/GettingStartedWritingClients).

Build
-----

    $ rebar get-deps compile

Run
---

    $ erl -pa ebin -env ERL_LIBS deps
    > application:ensure_all_started(yubi).

Use
---

    > CID = Your Client Id Here %% e.g. <<"1">>
    > SK = Your Yubico secret key in base64 encoded format
    > yubi:validate(yubi:test_prompt(), CID, base64:decode(SK)).
    OTP> cccccccbcjdifctrndncchkftchjlnbhvhtugdljibej
    valid

