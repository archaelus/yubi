%% @copyright Geoff Cant
%% @author Geoff Cant <nem@erlang.geek.nz>
%% @version {@vsn}, {@date} {@time}
%% @doc Yubikey soft token
%% @end
-module(yubi_token).

-compile(export_all).

from_hex(Str) ->
    << << (list_to_integer([C], 16)):4 >> || << C >> <= Str >>.

negate(Bin) ->
    << << (bnot Byte) >> || << Byte >> <= Bin >>.

decrypt(Key, Data) ->
    crypto:block_decrypt(aes_cbc128, Key, negate(Key), Data).

encrypt(Key, Data) ->
    crypto:block_encrypt(aes_cbc128, Key, negate(Key), Data).

decode_otp(<<PublicId:6/binary, EncryptedToken/binary>>, Key) ->
    Token = decrypt(Key, EncryptedToken),
    {PublicId, decode_token(Token)}.

decode_token(<<Uid:6/binary, Ctr:16/unsigned-little, Time:24/unsigned-little,
               SessionCtr, Rnd:16, CRC:16/unsigned-little>> = Token) ->
    {Uid, Ctr, Time, SessionCtr, Rnd,
     {token_checksum(Token), CRC}}.

token_checksum(Token) ->
    oc16_sum(Token).

%% 16bit ones complement checksum of a given binary
oc16(Bin) when is_binary(Bin) -> oc16(Bin,0).

oc16(<<A:16,B:16,Bin/binary>>,Sum) -> oc16(Bin,A+B+Sum);
oc16(<<A:16,B:8>>, Sum)  -> oc16_fold(A+(B bsl 8)+Sum);
oc16(<<A:16>>, Sum)  -> oc16_fold(A+Sum);
oc16(<<A:8>>, Sum) -> oc16_fold((A bsl 8)+Sum);
oc16(<<>>, Sum) -> oc16_fold(Sum).

%% fold 16-bit carry
oc16_fold(Sum) when Sum > 16#ffff ->
    oc16_fold((Sum band 16#ffff) + (Sum bsr 16));
oc16_fold(Sum) ->
    Sum.


%% The ones complement of the oc16 sum.
oc16_sum(Bin) -> (bnot oc16(Bin)) band 16#FFFF.
