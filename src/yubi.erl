%%%-------------------------------------------------------------------
%% @copyright Geoff Cant (2014)
%% @author Geoff Cant <nem@erlang.geek.nz>
%% @doc Yubikey OTP verification functions
%% @end
%%%-------------------------------------------------------------------

-module(yubi).
-compile(export_all).
%% API
-export([
        ]).

%%====================================================================
%% API
%%====================================================================

%%====================================================================
%% Internal functions
%%====================================================================

switch_prompt() ->
    os:cmd("osascript -e 'tell application \"yubiswitch\" to KeyOn'"),
    OTP = otp_prompt(),
    os:cmd("osascript -e 'tell application \"yubiswitch\" to KeyOff'"),
    OTP.

otp_prompt() ->
    {ok, [OTP]} = io:fread('OTP> ', "~s"),
    iolist_to_binary(OTP).

-spec validate(OTP::binary(), ClientId::iodata(), Secret::iodata()) -> any().
validate(OTP, ClientId, Secret) ->
    Nonce = nonce(),
    URL = verify_url(verify_url_base(), OTP, ClientId, Nonce, Secret),
    case hackney:request(get, URL, [], <<>>, []) of
        {ok, Code, _Hdrs, Client} when 200 =< Code, Code =< 299  ->
            case hackney:body(Client) of
                {ok, Bin} ->
                    Resp = parse_validate_response(Bin),
                    validate_response(Secret, Nonce, OTP, Resp);
                Else ->
                    Else
            end;
        Else ->
            Else
    end.

validator([]) -> valid;
validator([V | Rest]) ->
    case V() of
        valid ->
            validator(Rest);
        Else ->
            Else
    end.

validate_response(Secret, Nonce, OTP, Resp) ->
    validator([ fun () ->
                        validate_response_hmac(Secret, Resp)
                end,
                fun () ->
                        validate_response_nonce(Nonce, Resp)
                end,
                fun () ->
                        validate_response_otp(OTP, Resp)
                end,
                fun () ->
                        validate_response_status(Resp)
                end]).

validate_response_hmac(Secret, Resp) ->
    RespHmac = base64:decode(proplists:get_value(<<"h">>, Resp)),
    Props = lists:keysort(1,proplists:delete(<<"h">>, Resp)),
    case crypto:hmac(sha, Secret, params_to_hmac_string(Props)) of
        RespHmac ->
            valid;
        _Mismatch ->
            {error, invalid_hmac}
    end.

validate_response_nonce(Nonce, Resp) ->
    case proplists:get_value(<<"nonce">>, Resp) of
        Nonce -> valid;
        Else ->
            {error, {invalid_nonce, Else}}
    end.

validate_response_otp(OTP, Resp) ->
    case proplists:get_value(<<"otp">>, Resp) of
        OTP -> valid;
        Else ->
            {error, {invalid_otp, Else}}
    end.

validate_response_status(Resp) ->
    case proplists:get_value(<<"status">>, Resp) of
        <<"OK">> -> valid;
        <<"REPLAYED_OTP">> -> {error, {invalid_status, replayed_otp}};
        Else ->
            {error, {invalid_status, Else}}
    end.


parse_validate_response(Bin) ->
    [case binary:split(Line, <<"=">>) of
         [K,V] -> {K, V}
     end
     || Line <- binary:split(Bin, <<"\r\n">>, [global, trim])].

verify_url_base() ->
    {ok, Base} = application:get_env(yubi, verification_url_base),
    Base.

nonce() ->
    << << (hd(erlang:integer_to_list(C, 16))):8 >>
       || << C:4 >> <= crypto:rand_bytes(20) >>.

-spec valid_modhex(Str::binary()) -> valid | invalid.
valid_modhex(Str) when
      byte_size(Str) >= 32,
      byte_size(Str) =< 48 ->
    case re:run(Str, "^[cbdefghijklnrtuv]{32,48}$") of
        {match, _} ->
            valid;
        _ ->
            invalid
    end.

verify_url(Base, Otp, ClientId, Nonce, SecretKey) ->
    Params = verify_proplist(Otp, ClientId, Nonce),
    HmacString = params_to_hmac_string(Params),
    RequestHmac = base64:encode(crypto:hmac(sha, SecretKey, HmacString)),
    QS = hackney_url:qs([{<<"h">>, RequestHmac} |
                         Params]),
    [Base, "?", QS].

params_to_hmac_string(Props) ->
    hackney_bstr:join([ iolist_to_binary([K, "=", V])
                        || {K, V} <- Props ],
                      <<"&">>).

verify_proplist(Otp, ClientId, Nonce) ->
    lists:keysort(1, [{<<"id">>, iolist_to_binary(ClientId)},
                      {<<"nonce">>, iolist_to_binary(Nonce)},
                      {<<"otp">>, iolist_to_binary(Otp)}]).


read_api_key(File) ->
    {ok, PL} = file:consult(File),
    {proplists:get_value(client_id, PL),
     base64:decode(proplists:get_value(secret_key, PL))}.

write_api_key(CID, SK, File) ->
    file:write_file(File, io_lib:format("~p.~n~p.~n",
                                        [{client_id, CID},
                                         {secret_key, base64:encode(SK)}])).
