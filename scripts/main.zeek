module Amadey;

export {
	## Log stream identifier.
	redef enum Log::ID += { LOG };

	## The notice when Amadey C2 is observed.
	redef enum Notice::Type += { C2_Traffic_Observed, };

	## An option to enable detailed logs
	const enable_detailed_logs = T &redef;

	## Record type containing the column fields of the Amadey log.
	type Info: record {
		## Timestamp for when the activity happened.
		ts: time &log;
		## Unique ID for the connection.
		uid: string &log;
		## The connection's 4-tuple of endpoint addresses/ports.
		id: conn_id &log;
		## The direction of this C2 data.
		is_orig: bool &log;
		## The C2 data.
		payload: string &log;
	};

	## Default hook into Amadey logging.
	global log_amadey: event(rec: Info);

	## A default logging policy hook for the stream.
	global log_policy: Log::PolicyHook;

	## Indicator of a request related to Amadey
	redef enum HTTP::Tags += { URI_AMADEY_C2, };
}

# Make regex global so they are only compiled once.
global id_regex = /^id=[0-9]+/;
global vs_regex = /&vs=[0-9\.]+/;
global os_regex = /&os=[0-9]+/;
global bi_regex = /&bi=[01]/;
global ar_regex = /&ar=[01]/;
global pc_regex = /&pc=/;
global un_regex = /&un=/;

event http_entity_data(c: connection, is_orig: bool, length: count,
	data: string)
	{
	# Bail on anything not a post.
	if ( ! c?$http || ! c$http?$method || c$http$method != "POST" )
		return;

	if ( id_regex in data
		&& vs_regex in data
		&& os_regex in data
		&& bi_regex in data
		&& ar_regex in data
		&& pc_regex in data
		&& un_regex in data )
		{
		add c$http$tags[URI_AMADEY_C2];

		local msg = fmt("Potential Amadey C2 between source %s and dest %s (is_orig=%s) with payload in the sub field.",
			c$id$orig_h, c$id$resp_h, is_orig);

		if ( enable_detailed_logs )
			{
			local info = Info($ts=network_time(), $uid=c$uid, $id=c$id, $is_orig=is_orig,
				$payload=data);

			Log::write(Amadey::LOG, info);

			NOTICE([ $note=Amadey::C2_Traffic_Observed, $msg=msg, $sub=data, $conn=c, $identifier=cat(
				c$id$orig_h, c$id$resp_h) ]);
			}
		else
			# Do not suppress notices.
			NOTICE([ $note=Amadey::C2_Traffic_Observed, $msg=msg, $sub=data, $conn=c ]);
		}
	}

event zeek_init() &priority=5
	{
	if ( enable_detailed_logs )
		Log::create_stream(Amadey::LOG, [ $columns=Info, $ev=log_amadey,
			$path="amadey", $policy=Amadey::log_policy ]);
	}
