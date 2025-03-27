package filter

// 预定义的过滤规则
const (
	// HTTPFilter 只捕获HTTP流量（80、8080和443端口）
	HTTPFilter = "tcp port 80 or tcp port 8080 or tcp port 443"

	//HTTPNot443 bu捕获滤443端口的HTTP流量
	HTTPNot443 = "tcp and not (port 443)"

	// HTTPRequestFilter 只捕获HTTP请求流量
	HTTPRequestFilter = "tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x47455420 or tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x504F5354 or tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x48454144"

	// HTTPResponseFilter 只捕获HTTP响应流量
	HTTPResponseFilter = "tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x48545450"
)

var FilterMap = map[string]string{
	"n1": HTTPFilter,
	"n2": HTTPNot443,
	"n3": HTTPRequestFilter,
	"n4": HTTPResponseFilter,
}
