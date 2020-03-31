type agent_set: set[string];
type ip_dict: table[addr] of agent_set;

global IP:ip_dict;

event http_header(c:connection, is_orig:bool, name:string, value:string){
	local ip = c$http$id$orig_h;
	if(ip in IP){
		if(c$http?$user_agent)
		{
			add IP[ip][c$http$user_agent];
		}else{
			add IP[ip][""];
		}
	}
	else{
		if(c$http?$user_agent)
		{
			IP[ip] = set(c$http$user_agent);
		}else{
			IP[ip] = set("None");
		}
	}
}

event zeek_done()
{
	for(ip in IP){
		local cnt = 0;
		for(agent in IP[ip]){
			cnt += 1;
		}
		if(cnt>2){
			print fmt("%s is a proxy",ip);
		}
		cnt = 0;
	}
}

#Reference: https://docs.zeek.org/en/current/examples/

