%% Copyright (c) 2011, Anthony Ramine <nox@dev-extend.eu>
%%
%% Permission to use, copy, modify, and/or distribute this software for any
%% purpose with or without fee is hereby granted, provided that the above
%% copyright notice and this permission notice appear in all copies.
%%
%% THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
%% WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
%% MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
%% ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
%% WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
%% ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
%% OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

-module(cowboy_http_fcgi).
-behaviour(cowboy_http_handler).
-export([init/3, handle/2, terminate/2]).

-include("http.hrl").
-include_lib("eunit/include/eunit.hrl").

-type uint32() :: 0..(1 bsl 32 - 1).
-type option() :: {name, atom()} | {timeout, uint32()}
	| {script_dir, iodata()} | {path_root, iodata()}.
-type foldk_stdout_fun(Acc, NewAcc) ::
	fun((Acc, Buffer::binary() | eof, foldk_stdout_fun(Acc, NewAcc)) -> NewAcc).

-record(state, {server :: atom(), timeout :: uint32(), script_dir :: iodata(),
	path_root :: undefined | iodata(), https :: boolean()}).
-record(cgi_head, {status = 200 :: http_status(),
	type :: undefined | binary(), location :: undefined | binary(),
	headers = [] :: http_headers()}).

-spec init({tcp, http}, Req::#http_req{}, Opts::list(option()))
	-> {ok, Req::#http_req{}, State::#state{}}.
init({Transport, http}, Req, Opts) ->
	{name, Name} = lists:keyfind(name, 1, Opts),
	Timeout = case lists:keyfind(timeout, 1, Opts) of
		{timeout, To} -> To;
		false -> 15000
	end,
	ScriptDir = case lists:keyfind(script_dir, 1, Opts) of
		{script_dir, Sd} -> Sd;
		false -> undefined
	end,
	PathRoot = case lists:keyfind(path_root, 1, Opts) of
		{path_root, Pr} -> Pr;
		false -> ScriptDir
	end,
	Https = Transport =:= ssl,
	case whereis(Name) of
		Server when is_pid(Server) ->
			{ok, Req, #state{server=whereis(Name), timeout=Timeout,
				script_dir=ScriptDir, path_root=PathRoot, https=Https}}
	end.

-spec handle(Req::#http_req{}, State::#state{})
	-> {ok, Req::#http_req{}, State::#state{}}.
handle(Req=#http_req{path=Path, path_info=undefined}, State) ->
	% php-fpm complains when PATH_TRANSLATED isn't set for /ping and
	% /status requests and it's not non standard to send a empty value
	% if PathInfo isn't defined (or empty).
	handle_scriptname(Req, State, [{<<"PATH_TRANSLATED">>, <<>>}], Path);
handle(Req, State=#state{path_root=undefined}) ->
	% A path info is here but the handler doesn't have a path root.
	Req2 = cowboy_http_req:reply(500, [], [], Req),
	{ok, Req2, State};
handle(Req=#http_req{path=Path, path_info=[], raw_path=RawPath},
		State=#state{path_root=PathRoot}) ->
	case binary:last(RawPath) of
		$/ ->
			% Trailing slash means CGI path info is "/".
			handle_scriptname(Req, State, [
				{<<"PATH_INFO">>, <<"/">>},
				{<<"PATH_TRANSLATED">>, [PathRoot, $/]}
			], Path);
		_ ->
			% Same as with undefined path info.
			handle_scriptname(Req, State, [{<<"PATH_TRANSLATED">>, <<>>}], Path)
	end;
handle(Req=#http_req{path=Path, path_info=PathInfo},
		State=#state{path_root=PathRoot}) ->
	{CGIPathInfo, ScriptName} = path_info(PathInfo, Path),
	PathTranslated = [PathRoot, CGIPathInfo],
	handle_scriptname(Req, State, [
		{<<"PATH_TRANSLATED">>, PathTranslated},
		{<<"PATH_INFO">>, CGIPathInfo}
	], ScriptName).

-spec handle_scriptname(Req::#http_req{}, State::#state{},
	CGIParams::list({binary(), iodata()}),
	ScriptName::cowboy_dispatcher:path_tokens())
	-> {ok, Req::#http_req{}, State::#state{}}.
handle_scriptname(Req, State=#state{script_dir=undefined}, CGIParams, []) ->
	handle_req(Req, State, [{<<"SCRIPT_NAME">>, <<"/">>}|CGIParams]);
handle_scriptname(Req, State=#state{script_dir=undefined}, CGIParams,
		ScriptName) ->
	handle_req(Req, State, [
		{<<"SCRIPT_NAME">>, [[$/, Segment] || Segment <- ScriptName]}|CGIParams
	]);
handle_scriptname(Req, State, _CGIParams, []) ->
	% The handler should send a SCRIPT_FILENAME param but there was no path
	% provided.
	Req2 = cowboy_http_req:reply(500, [], [], Req),
	{ok, Req2, State};
handle_scriptname(Req, State=#state{script_dir=Dir}, CGIParams, ScriptName) ->
	CGIScriptName = [[$/, Segment] || Segment <- ScriptName],
	handle_req(Req, State, [
		{<<"SCRIPT_NAME">>, CGIScriptName},
		{<<"SCRIPT_FILENAME">>, [Dir, $/, lists:last(ScriptName)]} |
		CGIParams
	]).

-spec handle_req(Req::#http_req{}, State::#state{},
	CGIParams::list({binary(), iodata()}))
	-> {ok, Req::#http_req{}, State::#state{}}.
handle_req(Req=#http_req{method=Method, version=Version, raw_qs=RawQs,
		raw_host=RawHost, port=Port, headers=Headers},
		State=#state{server=Server, timeout=Timeout, https=Https}, CGIParams) ->
	{{Address, _Port}, Req1} = cowboy_http_req:peer(Req),
	AddressStr = inet_parse:ntoa(Address),
	% @todo Implement correctly the following parameters:
	% - AUTH_TYPE = auth-scheme token
	% - REMOTE_USER = user-ID token
	CGIParams1 = case Https of
		true -> [{<<"HTTPS">>, <<"1">>}|CGIParams];
		false -> CGIParams
	end,
	CGIParams2 = params(Headers, [
		{<<"GATEWAY_INTERFACE">>, <<"CGI/1.1">>},
		{<<"QUERY_STRING">>, RawQs},
		{<<"REMOTE_ADDR">>, AddressStr},
		{<<"REMOTE_HOST">>, AddressStr},
		{<<"REQUEST_METHOD">>, method(Method)},
		{<<"SERVER_NAME">>, RawHost},
		{<<"SERVER_PORT">>, integer_to_list(Port)},
		{<<"SERVER_PROTOCOL">>, protocol(Version)},
		{<<"SERVER_SOFTWARE">>, <<"Cowboy">>} |
		CGIParams1
	]),
	case ex_fcgi:begin_request(Server, responder, CGIParams2, Timeout) of
		error ->
			Req2 = cowboy_http_req:reply(502, [], [], Req1),
			{ok, Req2, State};
		{ok, Ref} ->
			Req3 = case cowboy_http_req:body(Req1) of
				{ok, Body, Req2} ->
					ex_fcgi:send(Server, Ref, Body),
					Req2;
				{error, badarg} ->
					Req1
			end,
			Fun = fun decode_cgi_head/3,
			{ok, Req4} = case foldk_stdout(#cgi_head{}, <<>>, Fun, Ref) of
				{Head, Rest, FoldkCont} ->
					case acc_body([], Rest, FoldkCont) of
						error ->
							cowboy_http_req:reply(502, [], [], Req3);
						timeout ->
							cowboy_http_req:reply(504, [], [], Req3);
						CGIBody ->
							send_response(Req3, Head, CGIBody)
					end;
				error ->
					cowboy_http_req:reply(502, [], [], Req3);
				timeout ->
					cowboy_http_req:reply(504, [], [], Req3)
			end,
			{ok, Req4, State}
	end.

-spec terminate(Req::#http_req{}, State::#state{}) -> ok.
terminate(_Req, _State) ->
	ok.

-spec path_info(PathInfo::cowboy_dispatcher:path_tokens(),
	Path::cowboy_dispatcher:path_tokens())
	-> {CGIPathInfo::iolist(), ScriptName::cowboy_dispatcher:path_tokens()}.
path_info(PathInfo, Path) ->
	path_info(lists:reverse(PathInfo), lists:reverse(Path), []).

-spec path_info(PathInfo::cowboy_dispatcher:path_tokens(),
	Path::cowboy_dispatcher:path_tokens(), CGIPathInfo::iolist())
	-> {CGIPathInfo::iolist(), ScriptName::cowboy_dispatcher:path_tokens()}.
path_info([Segment|PathInfo], [Segment|Path], CGIPathInfo) ->
	path_info(PathInfo, Path, [$/, Segment|CGIPathInfo]);
path_info([], Path, CGIPathInfo) ->
	{CGIPathInfo, lists:reverse(Path)}.

-spec method(Method::http_method()) -> Value::binary().
method('GET') ->
	<<"GET">>;
method('POST') ->
	<<"POST">>;
method('PUT') ->
	<<"PUT">>;
method('HEAD') ->
	<<"HEAD">>;
method('DELETE') ->
	<<"DELETE">>;
method('OPTIONS') ->
	<<"OPTIONS">>;
method('TRACE') ->
	<<"TRACE">>;
method(Method) when is_binary(Method) ->
	Method.

-spec protocol(Version::http_version()) -> Value::binary().
protocol({1, 0}) ->
	<<"HTTP/1.0">>;
protocol({1, 1}) ->
	<<"HTTP/1.1">>.

-spec params(Headers::http_headers(), Acc::list({binary(), iodata()}))
	-> Params::list({binary(), iodata()}).
params(Params, Acc) ->
	lists:foldl(fun ({Name, Value}, Acc1) ->
		case param(Name) of
			ignore ->
				Acc1;
			ParamName ->
				case Acc1 of
					[{ParamName, AccValue}|Acc2] ->
						% Value is counter-intuitively prepended to AccValue
						% because Cowboy accumulates headers in reverse order.
						[{ParamName, [Value, value_sep(Name)|AccValue]}|Acc2];
					_ ->
						[{ParamName, Value}|Acc1]
				end
		end
	end, Acc, lists:keysort(1, Params)).

-spec value_sep(Header::http_header()) -> char().
value_sep('Cookie') ->
	% Accumulate cookies using a semicolon because at least one known FastCGI
	% implementation (php-fpm) doesn't understand comma-separated cookies.
	$;;
value_sep(_Header) ->
	$,.

-spec param(Header::http_header()) -> Param::binary() | ignore.
param('Accept') ->
	<<"HTTP_ACCEPT">>;
param('Accept-Charset') ->
	<<"HTTP_ACCEPT_CHARSET">>;
param('Accept-Encoding') ->
	<<"HTTP_ACCEPT_ENCODING">>;
param('Accept-Language') ->
	<<"HTTP_ACCEPT_LANGUAGE">>;
param('Cache-Control') ->
	<<"HTTP_CACHE_CONTROL">>;
param('Content-Base') ->
	<<"HTTP_CONTENT_BASE">>;
param('Content-Encoding') ->
	<<"HTTP_CONTENT_ENCODING">>;
param('Content-Language') ->
	<<"HTTP_CONTENT_LANGUAGE">>;
param('Content-Length') ->
	<<"CONTENT_LENGTH">>;
param('Content-Md5') ->
	<<"HTTP_CONTENT_MD5">>;
param('Content-Range') ->
	<<"HTTP_CONTENT_RANGE">>;
param('Content-Type') ->
	<<"CONTENT_TYPE">>;
param('Cookie') ->
	<<"HTTP_COOKIE">>;
param('Etag') ->
	<<"HTTP_ETAG">>;
param('From') ->
	<<"HTTP_FROM">>;
param('If-Modified-Since') ->
	<<"HTTP_IF_MODIFIED_SINCE">>;
param('If-Match') ->
	<<"HTTP_IF_MATCH">>;
param('If-None-Match') ->
	<<"HTTP_IF_NONE_MATCH">>;
param('If-Range') ->
	<<"HTTP_IF_RANGE">>;
param('If-Unmodified-Since') ->
	<<"HTTP_IF_UNMODIFIED_SINCE">>;
param('Location') ->
	<<"HTTP_LOCATION">>;
param('Pragma') ->
	<<"HTTP_PRAGMA">>;
param('Range') ->
	<<"HTTP_RANGE">>;
param('Referer') ->
	<<"HTTP_REFERER">>;
param('User-Agent') ->
	<<"HTTP_USER_AGENT">>;
param('Warning') ->
	<<"HTTP_WARNING">>;
param('X-Forwarded-For') ->
	<<"HTTP_X_FORWARDED_FOR">>;
param(Name) when is_atom(Name) ->
	ignore;
param(Name) when is_binary(Name) ->
	<< "HTTP_", (<< << (param_char(C)) >> || << C >> <= Name >>)/binary >>.

-spec param_char(char()) -> char().
param_char($a) -> $A;
param_char($b) -> $B;
param_char($c) -> $C;
param_char($d) -> $D;
param_char($e) -> $E;
param_char($f) -> $F;
param_char($g) -> $G;
param_char($h) -> $H;
param_char($i) -> $I;
param_char($j) -> $J;
param_char($k) -> $K;
param_char($l) -> $L;
param_char($m) -> $M;
param_char($n) -> $N;
param_char($o) -> $O;
param_char($p) -> $P;
param_char($q) -> $Q;
param_char($r) -> $R;
param_char($s) -> $S;
param_char($t) -> $T;
param_char($u) -> $U;
param_char($v) -> $V;
param_char($w) -> $W;
param_char($x) -> $X;
param_char($y) -> $Y;
param_char($z) -> $Z;
param_char($-) -> $_;
param_char(Ch) -> Ch.

-spec foldk_stdout(Acc, Buffer::binary(), Fun::foldk_stdout_fun(Acc, NewAcc),
	Ref::reference()) -> NewAcc | error | timeout.
foldk_stdout(Acc, Buffer, Fun, Ref) ->
	receive Msg -> foldk_stdout(Acc, Buffer, Fun, Ref, Msg) end.

-spec foldk_stdout(Acc, Buffer::binary(), Fun::foldk_stdout_fun(Acc, NewAcc),
	Ref::reference(), Msg::term()) -> NewAcc | error | timeout.
foldk_stdout(Acc, Buffer, Fun, Ref, {ex_fcgi, Ref, Messages}) ->
	foldk_stdout2(Acc, Buffer, Fun, Ref, Messages);
foldk_stdout(_Acc, _Buffer, _Fun, Ref, {ex_fcgi_timeout, Ref}) ->
	timeout;
foldk_stdout(Acc, Buffer, Fun, Ref, _Msg) ->
	foldk_stdout(Acc, Buffer, Fun, Ref).

% We can't use ex_fcgi:message() type here because Cowboy doesn't really
% depend on ex_fcgi.
-spec foldk_stdout2(Acc, Buffer::binary(), Fun::foldk_stdout_fun(Acc, NewAcc),
	Ref::reference(), Messages::list(term())) -> NewAcc | error | timeout.
foldk_stdout2(Acc, Buffer, Fun, _Ref, [{stdout, eof}|_Messages]) ->
	foldk_stdout2(Acc, Buffer, Fun);
foldk_stdout2(Acc, Buffer, Fun, Ref, [{stdout, NewData}|Messages]) ->
	Cont = fun (NewAcc, Rest, NewFun) ->
		foldk_stdout2(NewAcc, Rest, NewFun, Ref, Messages)
	end,
	Fun(Acc, << Buffer/binary, NewData/binary >>, Cont);
foldk_stdout2(Acc, Buffer, Fun, _Ref,
		[{end_request, _CGIStatus, _AppStatus}|_Messages]) ->
	foldk_stdout2(Acc, Buffer, Fun);
foldk_stdout2(Acc, Buffer, Fun, Ref, [_Msg|Messages]) ->
	foldk_stdout2(Acc, Buffer, Fun, Ref, Messages);
foldk_stdout2(Acc, Buffer, Fun, Ref, []) ->
	foldk_stdout(Acc, Buffer, Fun, Ref).

-spec foldk_stdout2(Acc, Buffer::binary(), Fun::foldk_stdout_fun(Acc, NewAcc))
	-> NewAcc | error | timeout.
foldk_stdout2(Acc, <<>>, Fun) ->
	Cont = fun (_NewAcc, _NewBuffer, _NewFun) -> error end,
	Fun(Acc, eof, Cont);
foldk_stdout2(_Acc, _Buffer, _Fun) ->
	error.

-spec decode_cgi_head(Head::#cgi_head{}, Data::binary() | eof,
	foldk_stdout_fun(Head::#cgi_head{}, Head::#cgi_head{} | error | timeout))
	-> Head::#cgi_head{} | error | timeout.
decode_cgi_head(_Head, eof, _More) ->
	error;
decode_cgi_head(Head, Data, More) ->
	case erlang:decode_packet(httph_bin, Data, []) of
		{ok, Packet, Rest} ->
			decode_cgi_head(Head, Rest, More, Packet);
		{more, _} ->
			More(Head, Data, fun decode_cgi_head/3);
		_ ->
			error
	end.

-define(decode_default(Head, Rest, More, Field, Default, Value),
	case Head#cgi_head.Field of
		Default ->
			decode_cgi_head(Head#cgi_head{Field=Value}, Rest, More);
		_ ->
			% Decoded twice the same CGI header.
			error
	end).

-spec decode_cgi_head(Head::#cgi_head{}, Rest::binary(),
	foldk_stdout_fun(Head::#cgi_head{}, Head::#cgi_head{} | error | timeout),
	Packet::term()) -> Head::#cgi_head{} | error | timeout.
decode_cgi_head(Head, Rest, More, {http_header, _, <<"Status">>, _, Value}) ->
	?decode_default(Head, Rest, More, status, 200, Value);
decode_cgi_head(Head, Rest, More,
		{http_header, _, 'Content-Type', _, Value}) ->
	?decode_default(Head, Rest, More, type, undefined, Value);
decode_cgi_head(Head, Rest, More, {http_header, _, 'Location', _, Value}) ->
	?decode_default(Head, Rest, More, location, undefined, Value);
decode_cgi_head(Head, Rest, More,
		{http_header, _, << "X-CGI-", _NameRest >>, _, _Value}) ->
	% Dismiss any CGI extension header.
	decode_cgi_head(Head, Rest, More);
decode_cgi_head(Head=#cgi_head{headers=Headers}, Rest, More,
		{http_header, _, Name, _, Value}) ->
	decode_cgi_head(Head#cgi_head{headers=[{Name, Value}|Headers]}, Rest, More);
decode_cgi_head(Head, Rest, More, http_eoh) ->
	{Head, Rest, More};
decode_cgi_head(_Head, _Rest, _Name, _Packet) ->
	error.

-spec acc_body(Body::list(binary()), Data::binary() | eof,
	foldk_stdout_fun(Body::list(binary()),
		Body::list(binary())) | error | timeout)
	-> Body::list(binary()) | error | timeout.
acc_body(Acc, eof, _More) ->
	lists:reverse(Acc);
acc_body(Acc, Buffer, More) ->
	More([Buffer|Acc], <<>>, fun acc_body/3).

-spec send_response(Req::#http_req{}, Head::#cgi_head{}, Body::list(binary()))
	-> {ok, Req::#http_req{}}.
send_response(Req, #cgi_head{location= <<$/, _/binary>>}, _Body) ->
	% @todo Implement 6.2.2. Local Redirect Response.
	cowboy_http_req:reply(502, [], [], Req);
send_response(Req, Head=#cgi_head{location=undefined}, Body) ->
	% 6.2.1. Document Response.
	send_document(Req, Head, Body);
send_response(Req, Head, Body) ->
	% 6.2.3. Client Redirect Response.
	% 6.2.4. Client Redirect Response with Document.
	send_redirect(Req, Head, Body).

-spec send_document(Req::#http_req{}, Head::#cgi_head{}, Body::list(binary()))
	-> {ok, Req::#http_req{}}.
send_document(Req, #cgi_head{type=undefined}, _Body) ->
	cowboy_http_req:reply(502, [], [], Req);
send_document(Req, #cgi_head{status=Status, type=Type, headers=Headers},
		Body) ->
	reply(Req, Body, Status, Type, Headers).

-spec send_redirect(Req::#http_req{}, Head::#cgi_head{}, Body::list(binary()))
	-> {ok, Req::#http_req{}}.
send_redirect(Req, #cgi_head{status=Status= << $3, _/binary >>,
		type=Type, location=Location, headers=Headers}, Body) ->
	reply(Req, Body, Status, Type, [{'Location', Location}|Headers]);
send_redirect(Req, #cgi_head{type=Type, location=Location, headers=Headers},
		Body) ->
	reply(Req, Body, 302, Type, [{'Location', Location}|Headers]).

-spec reply(Req::#http_req{}, Body::list(binary()),
	Status::http_status(), Type::undefined | binary(), Headers::http_headers())
	-> {ok, Req::#http_req{}}.
%% @todo Filter headers like Content-Length.
reply(Req, Body, Status, undefined, Headers) ->
	cowboy_http_req:reply(Status, Headers, Body, Req);
reply(Req, Body, Status, Type, Headers) ->
	cowboy_http_req:reply(Status, [{'Content-Type', Type}|Headers], Body, Req).

-ifdef(TEST).

param_test() ->
	?assertEqual(
		<<"HTTP_X_NON_STANDARD_HEADER">>,
		param(<<"X-Non-Standard-Header">>)
	).

-endif.
