package gates

import "github.com/singlestore-labs/codegate"

// TODO: INFOSEC-3102 remove once principal validation stable
var S2IAMValidatePrincipal = codegate.New("S2IAMValidatePrincipal")
