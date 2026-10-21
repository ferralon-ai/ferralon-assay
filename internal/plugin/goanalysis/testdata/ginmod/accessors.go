package main

import "github.com/gin-gonic/gin"

// accessorSunk keeps the accessor sinks' arguments live.
var accessorSunk []any

// One sink per modeled *gin.Context accessor or binder, so each one's taint path is
// distinguishable: accessorsForm reads the request through every one of them.
func sinkDefaultQuery(v any)       { accessorSunk = append(accessorSunk, v) }
func sinkGetQuery(v any)           { accessorSunk = append(accessorSunk, v) }
func sinkQueryArray(v any)         { accessorSunk = append(accessorSunk, v) }
func sinkQueryMap(v any)           { accessorSunk = append(accessorSunk, v) }
func sinkGetPostForm(v any)        { accessorSunk = append(accessorSunk, v) }
func sinkPostFormArray(v any)      { accessorSunk = append(accessorSunk, v) }
func sinkGetHeader(v any)          { accessorSunk = append(accessorSunk, v) }
func sinkCookie(v any)             { accessorSunk = append(accessorSunk, v) }
func sinkGetRawData(v any)         { accessorSunk = append(accessorSunk, v) }
func sinkFullPath(v any)           { accessorSunk = append(accessorSunk, v) }
func sinkBind(v any)               { accessorSunk = append(accessorSunk, v) }
func sinkBindJSON(v any)           { accessorSunk = append(accessorSunk, v) }
func sinkBindQuery(v any)          { accessorSunk = append(accessorSunk, v) }
func sinkBindUri(v any)            { accessorSunk = append(accessorSunk, v) }
func sinkMustBindWith(v any)       { accessorSunk = append(accessorSunk, v) }
func sinkShouldBind(v any)         { accessorSunk = append(accessorSunk, v) }
func sinkShouldBindJSON(v any)     { accessorSunk = append(accessorSunk, v) }
func sinkShouldBindQuery(v any)    { accessorSunk = append(accessorSunk, v) }
func sinkShouldBindUri(v any)      { accessorSunk = append(accessorSunk, v) }
func sinkShouldBindHeader(v any)   { accessorSunk = append(accessorSunk, v) }
func sinkShouldBindWith(v any)     { accessorSunk = append(accessorSunk, v) }
func sinkShouldBindBodyWith(v any) { accessorSunk = append(accessorSunk, v) }

// sinkNotRequestData is reached only through HandlerName, which reads no request data.
func sinkNotRequestData(v any) { accessorSunk = append(accessorSunk, v) }

// login is a binding target.
type login struct{ User string }

func (s *server) accessorsForm(c *gin.Context) {
	sinkDefaultQuery(c.DefaultQuery("q", "none"))
	q, _ := c.GetQuery("q")
	sinkGetQuery(q)
	sinkQueryArray(c.QueryArray("ids"))
	sinkQueryMap(c.QueryMap("m"))
	f, _ := c.GetPostForm("f")
	sinkGetPostForm(f)
	sinkPostFormArray(c.PostFormArray("fs"))
	sinkGetHeader(c.GetHeader("X-Token"))
	ck, _ := c.Cookie("session")
	sinkCookie(ck)
	raw, _ := c.GetRawData()
	sinkGetRawData(string(raw))
	sinkFullPath(c.FullPath())
	sinkNotRequestData(c.HandlerName())

	var b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12 login
	_ = c.Bind(&b1)
	sinkBind(b1.User)
	_ = c.BindJSON(&b2)
	sinkBindJSON(b2.User)
	_ = c.BindQuery(&b3)
	sinkBindQuery(b3.User)
	_ = c.BindUri(&b4)
	sinkBindUri(b4.User)
	_ = c.MustBindWith(&b5, nil)
	sinkMustBindWith(b5.User)
	_ = c.ShouldBind(&b6)
	sinkShouldBind(b6.User)
	_ = c.ShouldBindJSON(&b7)
	sinkShouldBindJSON(b7.User)
	_ = c.ShouldBindQuery(&b8)
	sinkShouldBindQuery(b8.User)
	_ = c.ShouldBindUri(&b9)
	sinkShouldBindUri(b9.User)
	_ = c.ShouldBindHeader(&b10)
	sinkShouldBindHeader(b10.User)
	_ = c.ShouldBindWith(&b11, nil)
	sinkShouldBindWith(b11.User)
	_ = c.ShouldBindBodyWith(&b12, nil)
	sinkShouldBindBodyWith(b12.User)
}

func init() {
	r := gin.Default()
	r.POST("/accessors", (&server{}).accessorsForm)
}
