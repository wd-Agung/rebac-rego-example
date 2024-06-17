package app.rebac

import future.keywords.in

# create allow rule with the default of false
default allow := false

admin_roles := {"dipp_agency_admin", "dipp_agency_owner"}

# the input user
input_user := data.users[input.user]

allow {
	  some assignment in input_user.assignments
    assignment.role in admin_roles
}

# rule to return a list of allowed assignments
allowing_assignments[assignment] {
	# iterate the user assignments
	some assignment in input_user.assignments

	# check that the required action from the input is allowed by the current role
	input.action in data.roles[assignment.role].grants

	# check that the required resource from the input is reachable in the graph
	# by the current team 
	assignment.resource in graph.reachable(data.full_graph, {input.resource})
}

allow {
	# allow the user to perform the action on the resource if they have more than one allowing assignments
	count(allowing_assignments) > 0
}
