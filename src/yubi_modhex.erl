%% @copyright Geoff Cant
%% @author Geoff Cant <nem@erlang.geek.nz>
%% @version {@vsn}, {@date} {@time}
%% @doc Yubico Modhex en/decoding utility functions.
%% @end
-module(yubi_modhex).

-export([to_modhex/1
        ,from_modhex/1
        ,nibble_to_mh/1
        ,mh_to_nibble/1
        ]).

-include_lib("eunit/include/eunit.hrl").

to_modhex(Bin) ->
    << << (nibble_to_mh(Nibble)):8 >> || <<Nibble:4>> <= Bin >>.

from_modhex(Str) ->
    << << (mh_to_nibble(ModHex)):4 >> || <<ModHex:8>> <= Str >>.

nibble_to_mh(16#0) -> $c;
nibble_to_mh(16#1) -> $b;
nibble_to_mh(16#2) -> $d;
nibble_to_mh(16#3) -> $e;
nibble_to_mh(16#4) -> $f;
nibble_to_mh(16#5) -> $g;
nibble_to_mh(16#6) -> $h;
nibble_to_mh(16#7) -> $i;
nibble_to_mh(16#8) -> $j;
nibble_to_mh(16#9) -> $k;
nibble_to_mh(16#a) -> $l;
nibble_to_mh(16#b) -> $n;
nibble_to_mh(16#c) -> $r;
nibble_to_mh(16#d) -> $t;
nibble_to_mh(16#e) -> $u;
nibble_to_mh(16#f) -> $v.

mh_to_nibble($c) -> 16#0;
mh_to_nibble($b) -> 16#1;
mh_to_nibble($d) -> 16#2;
mh_to_nibble($e) -> 16#3;
mh_to_nibble($f) -> 16#4;
mh_to_nibble($g) -> 16#5;
mh_to_nibble($h) -> 16#6;
mh_to_nibble($i) -> 16#7;
mh_to_nibble($j) -> 16#8;
mh_to_nibble($k) -> 16#9;
mh_to_nibble($l) -> 16#a;
mh_to_nibble($n) -> 16#b;
mh_to_nibble($r) -> 16#c;
mh_to_nibble($t) -> 16#d;
mh_to_nibble($u) -> 16#e;
mh_to_nibble($v) -> 16#f.


to_modhex_test() ->
    ?assertMatch(<<"nlltvcct">>,
                 to_modhex(<< 16#ba,16#ad,16#f0,16#0d>>)).

from_modhex_test() ->
    ?assertMatch(<< 16#ba,16#ad,16#f0,16#0d>>,
                 from_modhex(<<"nlltvcct">>)).
