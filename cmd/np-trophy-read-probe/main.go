package main
import("context";"encoding/base64";"fmt";"io";"net/http";"os";"strings";"time";"openpak/np-account/internal/config";"openpak/np-common/coreclient";"openpak/np-common/ticket")
func main(){
 cfg,e:=config.Load(os.Getenv);if e!=nil{panic(e)}
 c,e:=coreclient.Dial(cfg.CoreAddress,cfg.CoreKey);if e!=nil{panic(e)};defer c.Close()
 ctx,cancel:=context.WithTimeout(context.Background(),15*time.Second);defer cancel()
 link,e:=c.GetLinkByOnlineID(ctx,"AndroidTest");if e!=nil{panic(e)}
 signer,e:=ticket.Load(cfg.TicketKeyPath);if e!=nil{panic(e)}
 raw,e:=signer.Issue(ticket.Identity{AccountID:link.AccountID,LinkID:link.LinkID,OnlineID:link.OnlineID,Country:"ie",Service:"IV0001-NPXS01001_00"},time.Minute);if e!=nil{panic(e)}
 for _,jid:=range []string{"AndroidTest@ie.np.np.playstation.net","Leia@ie.np.np.playstation.net"}{
 body:=`<nptrophy><ticket>`+base64.StdEncoding.EncodeToString(raw)+`</ticket><jid>`+jid+`</jid></nptrophy>`
 req,e:=http.NewRequestWithContext(ctx,"POST","http://127.0.0.1:8003/trophy/sec/get_multi_user_info_privacy",strings.NewReader(body));if e!=nil{panic(e)}
 resp,e:=http.DefaultClient.Do(req);if e!=nil{panic(e)}
 data,e:=io.ReadAll(io.LimitReader(resp.Body,4096));resp.Body.Close();if e!=nil{panic(e)}
 fmt.Println(jid,resp.StatusCode,string(data));if resp.StatusCode!=200{os.Exit(1)}
 }
}
