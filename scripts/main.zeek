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

	function amadey_match(state: signature_state, data: string): bool
		{
		local msg = fmt("Potential Amadey C2 between source %s and dest %s (is_orig=%s) with payload in the sub field.",
		    state$conn$id$orig_h, state$conn$id$resp_h, state$is_orig);

		if ( enable_detailed_logs )
			{
			local info = Info($ts=network_time(), $uid=state$conn$uid, $id=state$conn$id,
			    $is_orig=state$is_orig, $payload=data);

			Log::write(Amadey::LOG, info);

			NOTICE([ $note=Amadey::C2_Traffic_Observed, $msg=msg, $sub=data,
			    $conn=state$conn, $identifier=cat(
			    state$conn$id$orig_h, state$conn$id$resp_h) ]);
			}
		else
			# Do not suppress notices.
			NOTICE([ $note=Amadey::C2_Traffic_Observed, $msg=msg, $sub=data,
			    $conn=state$conn ]);

		return T;
		}
}

event zeek_init() &priority=5
	{
	if ( enable_detailed_logs )
		Log::create_stream(Amadey::LOG, [ $columns=Info, $ev=log_amadey,
		    $path="amadey", $policy=Amadey::log_policy ]);
	}
