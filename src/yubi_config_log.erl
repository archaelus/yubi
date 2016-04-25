%% @copyright Geoff Cant
%% @author Geoff Cant <nem@erlang.geek.nz>
%% @version {@vsn}, {@date} {@time}
%% @doc Yubikey Personalization Tool
%% @end
-module(yubi_config_log).

-export([from_file/1]).

from_file(File) ->
    {ok, F} = file:open(File, [binary, raw, read]),
    Entries = each_line(file:read_line(F), [], F),
    file:close(F),
    Entries.

each_line({ok, Line}, Acc, F) ->
    case binary:split(Line, <<",">>, [global]) of
        [<<"LOGGING START">>, _] ->
            each_line(file:read_line(F), Acc, F);
        [Type, DateTime, Slot, PublicId, PrivateId, AESKey | _] ->
            Acc1 = [{Type, DateTime, Slot, PublicId, PrivateId, AESKey} | Acc],
            each_line(file:read_line(F), Acc1, F)
    end;
each_line(eof, Acc, _F) ->
    lists:reverse(Acc);
each_line(Err = {error, _Reason}, _Acc, _F) ->
    Err.
