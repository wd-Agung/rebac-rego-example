package app.rebac

import future.keywords.in

# # rule to return the resource instances by ids
# files[id] := file_instance {
# 	# iterate the resource instances of some file_instance in data.files
# 	some file_instance in data.files
# 	id := sprintf("file:%s",[file_instance.id])
# }
# 
# # rule to return teams by ids
# teams[id] := team_instance {
# 	# Iterate the teams 
# 	some team_instance in data.teams
# 	id := sprintf("team:%s",[team_instance.id])
# }
# 
# organizations[id] := organization_instance {
# 	some organization_instance in data.organizations
#     id := sprintf("organization:%s",[organization_instance.id])
# }

# assets := data.assets
# campaigns := data.campaigns
# layouts := data.layouts
# brands := data.brands
# agencies := data.agencies

# return a full graph mapping of each subject to the object it has reference to
# full_graph[subject] := ref_object {
# 	some subject, object_instance in object.union_n([campaigns, layouts, brands, agencies])

# 	# get the parent_id the subject is referring
# 	ref_object := [object.get(object_instance, "parent_id", null)]
# }

# opa eval --data root.rego --profile --format=pretty 'data.rebac.allow'

# rule to return users by ids
# users[id] := user {
# 	some user in data.users
# 	id := user.id
# }

# the input user
input_user := data.users[input.user]

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

# create allow rule with the default of false
default allow := false

allow {
	# allow the user to perform the action on the resource if they have more than one allowing assignments
	count(allowing_assignments) > 0
}
