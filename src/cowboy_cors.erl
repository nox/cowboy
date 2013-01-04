%% Copyright (c) 2012, Anthony Ramine <n.oxyde@gmail.com>
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

-module(cowboy_cors).

%% API.
-export([handle/2]).
-export([is_allowed_origin/2]).

-type origin_rule()
	:: {binary(), cowboy_dispatcher:match_rule(), non_neg_integer()}.
-type origins() ::  '*' | [origin_rule()].
-type options() :: [
	{allow_origins, origins()} |
	{allow_methods, '*' | [binary()]} |
	{allow_headers, '*' | [binary()]} |
	{max_age, non_neg_integer()} |
	{expose_headers, [binary()]} |
	{allow_credentials, boolean()}
].

-export_type([origins/0]).
-export_type([options/0]).

-define(DEFAULT_MAX_AGE, 300).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

%% API.

-spec handle(options(), cowboy_req:req()) -> {error, cowboy_req:req()}
	| {no_origin, cowboy_req:req()} | {preflight_request, cowboy_req:req()}
	| {actual_request, cowboy_req:req()}.
handle(Opts, Req) ->
	case cowboy_req:parse_header(<<"origin">>, Req) of
		{error, badarg} ->
			{ok, Req2} = cowboy_req:reply(400, Req),
			{error, Req2};
		{ok, undefined, Req2} ->
			%% If the Origin header is not present terminate this set of steps.
			%% The request is outside the scope of this specification.
			{no_origin, Req2};
		{ok, Origin, Req2} ->
			AllowOrigins = proplists:get_value(allow_origins, Opts, []),
			case is_allowed_origin(Origin, AllowOrigins) of
				true ->
					handle(Opts, Req2, Origin);
				false ->
					%% If the value of the Origin header is not a case-sensitive
					%% match for any of the values in list of origins, do not
					%% set any additional headers and terminate this set of
					%% steps.
					{ok, Req3} = cowboy_req:reply(403, Req),
					{error, Req3}
			end
	end.

-spec is_allowed_origin(cowboy_http:origin(), origins()) -> boolean().
is_allowed_origin(null, _) ->
	false;
is_allowed_origin(_, '*') ->
	true;
is_allowed_origin(Origin, AllowOrigins) ->
	lists:any(fun (Rule) -> match_origin(Origin, Rule) end, AllowOrigins).

%% Internal.

-spec handle(options(), cowboy_req:req(), cowboy_http:origin())
	-> {error, cowboy_req:req()} | {preflight_request, cowboy_req:req()}
	| {actual_request, cowboy_req:req()}.
handle(Opts, Req, Origin) ->
	case cowboy_req:method(Req) of
		{<<"OPTIONS">>, Req2} ->
			%% If there is no Access-Control-Request-Method header or if parsing
			%% failed, do not set any additional headers and terminate this set
			%% of steps. The request is outside the scope of this specification.
			case cowboy_req:parse_header(
					<<"access-control-request-method">>, Req) of
				{error, badarg} ->
					%% Parsing failed.
					{ok, Req3} = cowboy_req:reply(400, Req2),
					{error, Req3};
				{ok, undefined, Req2} ->
					%% No Access-Control-Request-Method means this is an actual
					%% OPTIONS request.
					handle_actual_request(Opts, Req2, Origin);
				{ok, Method2, Req2} ->
					handle_preflight_request(Opts, Req2, Origin, Method2)
			end;
		{_, Req2} ->
			handle_actual_request(Opts, Req2, Origin)
	end.

-spec handle_preflight_request(options(), cowboy_req:req(),
		cowboy_http:origin(), binary())
	-> {error, cowboy_req:req()} | {preflight_request, cowboy_req:req()}.
handle_preflight_request(Opts, Req, Origin, Method) ->
	case cowboy_req:parse_header(<<"access-control-request-headers">>, Req) of
		{ok, ReqHeaders, Req2} ->
			case check_method(Method, Opts) of
				{ok, AllowMethods} ->
					case check_headers(ReqHeaders, Opts) of
						{ok, AllowHeaders} ->
							Headers = preflight_headers(
								Origin, AllowMethods, AllowHeaders, Opts),
							{ok, Req3} = cowboy_req:reply(204, Headers, Req2),
							{preflight_request, Req3};
						error ->
							{ok, Req3} = cowboy_req:reply(403, Req2),
							{error, Req3}
					end;
				error ->
					{ok, Req3} = cowboy_req:reply(405, Req2),
					{error, Req3}
			end;
		{error, badarg} ->
			%% If parsing failed do not set any additional headers and terminate
			%% this set of steps. The request is outside the scope of this
			%% specification.
			{ok, Req2} = cowboy_req:reply(400, Req),
			{error, Req2}
	end.

-spec handle_actual_request(options(), cowboy_req:req(), cowboy_http:origin())
	-> {actual_request, cowboy_req:req()}.
handle_actual_request(Opts, Req, Origin) ->
	Req2 = cowboy_req:set_resp_headers(actual_headers(Origin, Opts), Req),
	{actual_request, Req2}.

-spec check_method(binary(), options()) -> {ok, [binary()]} | error.
check_method(Method, Opts) ->
	case proplists:get_value(allow_methods, Opts, []) of
		'*' ->
			%% Always matching is acceptable since the list of methods can be
			%% unbounded.
			{ok, [Method]};
		AllowMethods ->
			case lists:member(Method, AllowMethods) of
				true ->
					{ok, AllowMethods};
				false ->
					%% If method is not a case-sensitive match for any of the
					%% values in list of methods do not set any additional
					%% headers and terminate this set of steps.
					error
			end
	end.

-spec check_headers([binary()], options()) -> {ok, [binary()]} | error.
check_headers(Headers, Opts) ->
	case proplists:get_value(allow_headers, Opts, []) of
		'*' ->
			%% Always matching is acceptable since the list of headers can be
			%% unbounded.
			{ok, Headers};
		AllowHeaders ->
			case lists:all(
					fun (Header) -> lists:member(Header, AllowHeaders) end,
					Headers) of
				true ->
					{ok, AllowHeaders};
				false ->
					%% If any of the header field-names is not a ASCII
					%% case-insensitive match for any of the values in list of
					%% headers do not set any additional headers and terminate
					%% this set of steps.
					error
			end
	end.

-spec preflight_headers(cowboy_http:origin(), [binary()], [binary()], options())
	-> cowboy_http:headers().
preflight_headers(Origin, AllowMethods, AllowHeaders, Opts) ->
	%% Optionally add a single Access-Control-Max-Age header with as value the
	%% amount of seconds the user agent is allowed to cache the result of the
	%% request.
	MaxAge = list_to_binary(
		integer_to_list(proplists:get_value(
			max_age, Opts, ?DEFAULT_MAX_AGE))),
	CommonHeaders = common_headers(Origin, Opts),
	PreflightHeaders = [
		{<<"access-control-max-age">>, MaxAge},
		{<<"access-control-allow-methods">>, comma_list(AllowMethods)},
		{<<"access-control-allow-headers">>, comma_list(AllowHeaders)}
	],
	PreflightHeaders ++ CommonHeaders.

-spec actual_headers(cowboy_http:origin(), options()) -> cowboy_http:headers().
actual_headers(Origin, Opts) ->
	ExposeHeaders = proplists:get_value(expose_headers, Opts, []),
	CommonHeaders = common_headers(Origin, Opts),
	%% If the list of exposed headers is not empty add one or more
	%% Access-Control-Expose-Headers headers, with as values the header field
	%% names given in the list of exposed headers.
	ActualHeaders = [
		{<<"access-control-expose-headers">>, comma_list(ExposeHeaders)}
			|| ExposeHeaders =/= []
	],
	ActualHeaders ++ CommonHeaders.

-spec common_headers(cowboy_http:origin(), options()) -> cowboy_http:headers().
common_headers(Origin, Opts) ->
	AllowOrigins = proplists:get_value(allow_origins, Opts, []),
	AllowCredentials = proplists:get_bool(allow_credentials, Opts),
	AllowOrigin = case {AllowOrigins, AllowCredentials} of
		{'*', false} ->
			%% The string "*" cannot be used for a resource that supports
			%% credentials.
			<<"*">>;
		_ ->
			%% Otherwise, add a single Access-Control-Allow-Origin header,
			%% with either the value of the Origin header or the string "*" as
			%% value.
			cowboy_http:origin_to_iodata(Origin)
	end,
	Headers = [
		{<<"access-control-allow-origin">>, AllowOrigin}
	],
	%% If the resource supports credentials (...) add a single
	%% Access-Control-Allow-Credentials header with the case-sensitive string
	%% "true" as value.
	Headers ++ [
		{<<"access-control-allow-credentials">>, <<"true">>} || AllowCredentials
	].

-spec comma_list([iodata()]) -> iodata().
comma_list([]) ->
	[];
comma_list([Value | Rest]) ->
	[Value | [ [$,, V] || V <- Rest ]].

-spec match_origin(cowboy_http:origin(), origin_rule()) -> boolean().
match_origin({Scheme, Host, Port}, {Scheme, Rule, Port}) ->
	case cowboy_dispatcher:match_host(Host, Rule) of
		{true, _, _} -> true;
		false -> false
	end;
match_origin({_, _, _}, {_, _, _}) ->
	false.

%% Tests.

-ifdef(TEST).

is_allowed_origin_test_() ->
	%% {Name, Origin, AllowOrigins, Result}
	Tests = [
		{"null origin with empty origins", null, [], false},
		{"null origin with allowed star", null, '*', false},
		{
			"http origin with empty origins",
			{<<"http">>, [<<"erlang">>, <<"fr">>], 80}, [], false
		},
		{
			"http origin with allowed star",
			{<<"http">>, [<<"erlang">>, <<"fr">>], 80}, '*', true
		},
		{
			"bad scheme",
			{<<"http">>, <<"erlang.fr">>, 80},
			[{<<"https">>, [<<"erlang">>, <<"fr">>], 80}],
			false
		},
		{
			"bad port",
			{<<"http">>, <<"erlang.fr">>, 80},
			[{<<"http">>, [<<"erlang">>, <<"fr">>], 8080}],
			false
		},
		{
			"bad host",
			{<<"http">>, <<"erlang.fr">>, 80},
			[{<<"http">>, [<<"coffeescript">>, <<"org">>], 80}],
			false
		},
		{
			"any http origin",
			{<<"http">>, [<<"erlang">>, <<"fr">>], 80},
			[{<<"http">>, '_', 80}],
			true
		},
		{
			"any subdomain origin",
			{<<"http">>, <<"doc.erlang.fr">>, 80},
			[{<<"http">>, ['...', <<"erlang">>, <<"fr">>], 80}],
			true
		},
		{
			"multiple origins",
			{<<"http">>, <<"www.erlang.se">>, 80},
			[
				{<<"http">>, [<<"erlang">>, <<"fr">>], 80},
				{<<"http">>, ['...', <<"erlang">>, <<"se">>], 80}
			],
			true
		}
	],
	[{Name, fun() -> R = is_allowed_origin(Origin, Os) end}
		|| {Name, Origin, Os, R} <- Tests].

preflight_headers_test_() ->
	%% {Name, Origin, Methods, Headers, Opts, Result}
	Tests = [
		{
			"empty options",
			{<<"http">>, <<"erlang.fr">>, 80},
			[], [], [],
			[
				{<<"access-control-allow-headers">>, <<>>},
				{<<"access-control-allow-methods">>, <<>>},
				{<<"access-control-allow-origin">>, <<"http://erlang.fr">>},
				{<<"access-control-max-age">>, <<"300">>}
			]
		},
		{
			"allow methods",
			{<<"http">>, <<"erlang.fr">>, 80},
			[<<"GET">>, <<"HEAD">>, <<"POST">>], [], [],
			[
				{<<"access-control-allow-headers">>, <<>>},
				{<<"access-control-allow-methods">>, <<"GET,HEAD,POST">>},
				{<<"access-control-allow-origin">>, <<"http://erlang.fr">>},
				{<<"access-control-max-age">>, <<"300">>}
			]
		},
		{
			"allow headers",
			{<<"http">>, <<"erlang.fr">>, 80},
			[], [<<"authorization">>, <<"content-type">>], [],
			[
				{<<"access-control-allow-headers">>,
					<<"authorization,content-type">>},
				{<<"access-control-allow-methods">>, <<>>},
				{<<"access-control-allow-origin">>, <<"http://erlang.fr">>},
				{<<"access-control-max-age">>, <<"300">>}
			]
		},
		{
			"custom max age",
			{<<"http">>, <<"erlang.fr">>, 80},
			[], [], [{max_age, 18000}],
			[
				{<<"access-control-allow-headers">>, <<>>},
				{<<"access-control-allow-methods">>, <<>>},
				{<<"access-control-allow-origin">>, <<"http://erlang.fr">>},
				{<<"access-control-max-age">>, <<"18000">>}
			]
		}
	],
	[{Name, fun() ->
				R = lists:sort([{N, iolist_to_binary(V)}
						|| {N, V} <- preflight_headers(Origin, Ms, Hs, Opts)])
			end}
		|| {Name, Origin, Ms, Hs, Opts, R} <- Tests].

actual_headers_test_() ->
	%% {Name, Origin, Opts, Result}
	Tests = [
		{
			"empty options",
			{<<"http">>, <<"erlang.fr">>, 80}, [],
			[
				{<<"access-control-allow-origin">>, <<"http://erlang.fr">>}
			]
		},
		{
			"expose headers",
			{<<"http">>, <<"erlang.fr">>, 80},
			[{expose_headers, [<<"link">>, <<"x-powered-with">>]}],
			[
				{<<"access-control-allow-origin">>, <<"http://erlang.fr">>},
				{<<"access-control-expose-headers">>,
					<<"link,x-powered-with">>}
			]
		}
	],
	[{Name, fun() ->
				R = lists:sort([{N, iolist_to_binary(V)}
						|| {N, V} <- actual_headers(Origin, Opts)])
			end}
		|| {Name, Origin, Opts, R} <- Tests].

common_headers_test_() ->
	%% {Name, Origin, Opts, Result}
	Tests = [
		{
			"empty options",
			{<<"http">>, <<"erlang.fr">>, 80}, [],
			[{<<"access-control-allow-origin">>, <<"http://erlang.fr">>}]
		},
		{
			"allow credentials",
			{<<"http">>, <<"erlang.fr">>, 80}, [{allow_credentials, true}],
			[
				{<<"access-control-allow-credentials">>, <<"true">>},
				{<<"access-control-allow-origin">>, <<"http://erlang.fr">>}
			]
		},
		{
			"wilcard allowed origin",
			{<<"http">>, <<"erlang.fr">>, 80}, [{allow_origins, '*'}],
			[{<<"access-control-allow-origin">>, <<"*">>}]
		},
		{
			"wilcard allowed origin with credentials",
			{<<"http">>, <<"erlang.fr">>, 80},
			[{allow_origins, '*'}, {allow_credentials, true}],
			[
				{<<"access-control-allow-credentials">>, <<"true">>},
				{<<"access-control-allow-origin">>, <<"http://erlang.fr">>}
			]
		}
	],
	[{Name, fun() ->
				R = lists:sort([{N, iolist_to_binary(V)}
						|| {N, V} <- common_headers(Origin, Opts)])
			end}
		|| {Name, Origin, Opts, R} <- Tests].

comma_list_test_() ->
	%% {Values, Result}
	Tests = [
		{[], <<>>},
		{[<<"foo">>, <<"bar">>], <<"foo,bar">>}
	],
	[{R, fun() -> R = iolist_to_binary(comma_list(V)) end} || {V, R} <- Tests].

-endif.
