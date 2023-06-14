module Amadey;

export {
	## Log stream identifier.
	redef enum Log::ID += { LOG };

	## The notice when njRAT C2 is observed.
    redef enum Notice::Type += {
        Amadey,
    };

	## Record type containing the column fields of the NJRAT log.
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
}

redef record connection += {
	amadey: Info &optional;
};

# Initialize logging state.
hook set_session(c: connection)
	{
	if ( c?$amadey )
		return;

	c$amadey = Info($ts=network_time(), $uid=c$uid, $id=c$id, $is_orig=T, $payload="");
	}

function emit_log(c: connection)
	{
	if ( ! c?$amadey )
		return;

	Log::write(Amadey::LOG, c$amadey);
	delete c$amadey;
	}

event http_entity_data(c: connection, is_orig: bool, length: count, data: string)
	{
	if (/id=[0-9]+/ in data &&
		/&vs=[0-9\.]+/ in data && 
		/&os=[0-9]+/ in data &&
		/&pc=/ in data &&
		/&un=/ in data)
		{
		# This is probably Amadey!
		hook set_session(c);

		c$amadey$payload = data;
		c$amadey$is_orig = is_orig;

		emit_log(c);

		NOTICE([$note=Amadey::Amadey,
				$msg=fmt("Potential Amadey C2 between source %s and dest %s", c$id$orig_h, c$id$resp_h),
				$conn=c,
				$identifier=cat(c$id$orig_h,c$id$resp_h)]);
		}
	}

event zeek_init() &priority=5
	{
	Log::create_stream(Amadey::LOG, [$columns=Info, $ev=log_amadey, $path="amadey"]);
	}