package forwardproxy

import (
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"

	"context"

	caddy "github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/go-co-op/gocron/v2"
	"github.com/gorilla/sessions"
	_ "github.com/mattn/go-sqlite3"
)

type User struct {
	Username     string    `json:"username"`
	Password     string    `json:"password"`
	MaxIPs       int       `json:"max_ips"`
	ExpiryDate   time.Time `json:"expiry_date"`
	Email        string    `json:"email"`
	Tags         string    `json:"tags"`
	Traffic      int64     `json:"traffic"`       //用户使用的当前流量
	TotalTraffic int64     `json:"total_traffic"` //用户总流量
	TrafficLimit bool      `json:"traffic_limit"` //是否用启流量限额
	MonthlyLimit int64     `json:"monthly_limit"` //每月流量限额
}

type Config struct {
	TrafficThreshold      int64  `yaml:"trafficThreshold" json:"trafficThreshold"`           //超过多少字节的缓存才进行动作记录
	AccessLogSize         int    `yaml:"accessLogSize" json:"accessLogSize"`                 //记录的最大动作数
	EnableAccessLog       bool   `yaml:"enableAccessLog" json:"enableAccessLog"`             //是否记录动作
	MaxTraffic            int64  `yaml:"maxTraffic" json:"maxTraffic"`                       //userlist页面总流量进度条的最大值
	DailyTraffic          int64  `yaml:"dailyTraffic" json:"dailyTraffic"`                   //userlist页面实时流量进度条的最大值
	IPExpiryDuration      int    `yaml:"ipExpiryDuration" json:"IPExpiryDuration"`           //以秒为单位的最大活跃时间
	UserTrafficCheckLevel int    `yaml:"userTrafficCheckLevel" json:"userTrafficCheckLevel"` //用户流量检查的精细程度,=2为每小时检查一次,=3为每次连接都检查.<2为默认每天凌晨4点检查.
	TaskExecutionHours    int    `yaml:"taskExecutionHours" json:"taskExecutionHours"`       //多少小时执行任务的小时数
	TrafficResetHour      string `yaml:"trafficResetHour" json:"trafficResetHour"`           //表示北京时间第天重置流量统计的钟数用整数(0-23)表示 eg: 07:25:45
	MonthlyRestartDay     int    `yaml:"monthlyRestartDay" json:"monthlyRestartDay"`         // 服务器时间每月重启的日期天数(跟服务器重置流量日期对应)
}

type UserManager struct {
	mu                 sync.RWMutex //user数据库的锁
	logMu              sync.RWMutex //日志数据库的锁
	caddyfileMu        sync.RWMutex //caddyfile文件的锁
	userDB             *sql.DB
	logDB              *sql.DB
	template           *template.Template
	tmplUser           *template.Template
	store              *sessions.CookieStore
	config             *Config
	scheduledTaskSetup bool //保证定时任务只创建一次
}

// UserConfig ----------------------hotyi----------------------------------

type UserConfig struct {
	userExpiry          map[string]time.Time            //用户期限
	userIPLimits        map[string]int                  //最大ip数
	activeIPs           map[string]map[string]time.Time //活动ip数
	userTraffic         map[string]int64                //用户流量统计
	currentMonthTraffic map[string]int64                // 当前月已使用流量
	monthlyLimit        map[string]int64                //用户访问月上限
	userAccessLog       map[string]*Accesslog           //用户访问日志
	mu                  sync.RWMutex                    //sync.Mutex                      // 保护共享资源的锁
}

type Accesslog struct {
	Entries []*AccessEntry
	index   int
}

type AccessEntry struct {
	Time      time.Time
	IP        string
	Host      string
	Path      string
	UserAgent string
}

// 全局变量
var (
	shareglobalUserConfig *UserConfig
	shareuserManager      *UserManager
	routes                caddyhttp.RouteList
	userConfigOnce        sync.Once
	usermanagerOnce       sync.Once
)

// LoadMonthlyLimits 读取月限额
func LoadMonthlyLimits() error {
	//从数据库加截月上限数据
	rows, err := shareuserManager.userDB.Query(`
SELECT username, current_month_traffic, monthly_limit
FROM users
WHERE traffic_limit > 0 
  AND expiry_date > CURRENT_TIMESTAMP
  AND monthly_limit > current_month_traffic
ORDER BY monthly_limit DESC;
`)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var username string
		var currentMonthTraffic, monthlyLimit int64
		if err := rows.Scan(&username, &currentMonthTraffic, &monthlyLimit); err != nil {
			return err
		}
		shareglobalUserConfig.mu.Lock()
		shareglobalUserConfig.monthlyLimit[username] = monthlyLimit
		shareglobalUserConfig.currentMonthTraffic[username] = currentMonthTraffic
		shareglobalUserConfig.mu.Unlock()
	}
	return rows.Err()
}

// LoadAllMonthlyLimits 加载所有用户的月流量限额信息，包括已超限的用户
func LoadAllMonthlyLimits() error {
	rows, err := shareuserManager.userDB.Query(`
		SELECT username, current_month_traffic, monthly_limit FROM users WHERE traffic_limit = 1
	`)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var username string
		var currentMonthTraffic, monthlyLimit int64
		if err := rows.Scan(&username, &currentMonthTraffic, &monthlyLimit); err != nil {
			return err
		}
		shareglobalUserConfig.mu.Lock()
		shareglobalUserConfig.monthlyLimit[username] = monthlyLimit
		shareglobalUserConfig.currentMonthTraffic[username] = currentMonthTraffic
		shareglobalUserConfig.mu.Unlock()
	}
	return rows.Err()
}

// 直接从数据库中检查用户的流量使用情况,在系统重开时调用 2025-3-17 ,
// checkUserTrafficInDB 直接从数据库中检查用户的流量使用情况

// GetUserConfig 初始化全局 UserConfig
func GetUserConfig() *UserConfig {
	userConfigOnce.Do(func() {
		shareglobalUserConfig = &UserConfig{
			userExpiry:          make(map[string]time.Time),
			userIPLimits:        make(map[string]int),
			activeIPs:           make(map[string]map[string]time.Time),
			userTraffic:         make(map[string]int64), //初始化用户流量统计
			currentMonthTraffic: make(map[string]int64),
			monthlyLimit:        make(map[string]int64), //用户访问月上限
			userAccessLog:       make(map[string]*Accesslog),
		}
		// 只有在 shareuserManager 不为 nil 时才加载月限额数据
		if shareuserManager != nil && shareuserManager.config.UserTrafficCheckLevel >= 3 {
			if err := LoadAllMonthlyLimits(); err != nil {
				fmt.Printf("Warning: Error loading monthly limits: %v\n", err)
			}
		}
	})
	return shareglobalUserConfig
}

// EditSession 保存编辑用户的日志
type EditSession struct {
	OriginalExpiryDate   string
	OriginalMaxIPs       int
	OriginalTags         string
	OriginalTrafficLimit bool
	OriginalMonthlyLimit int64
}

var editSessions = make(map[string]EditSession)

/*// 添加测试数据到userTraffic-删之 hotyi
func addTestDataToUserTraffic() {

	shareglobalUserConfig.mu.Lock()
	fmt.Printf("添加测试数据\n")

	//添加测试数据
	shareglobalUserConfig.userTraffic["hotyi"] = 9999999999
	shareglobalUserConfig.userTraffic["007"] = 4423725761
	shareglobalUserConfig.userTraffic["WUYOU"] = 816238379
	shareglobalUserConfig.userTraffic["hhshljmlq"] = 754478962
	shareglobalUserConfig.userTraffic["llh203"] = 239802701
	shareglobalUserConfig.userTraffic["WUYOU"] = 816238379
	shareglobalUserConfig.userTraffic["tom"] = 453056147
	now := time.Now()
	shareglobalUserConfig.activeIPs["007"] = make(map[string]time.Time)
	shareglobalUserConfig.activeIPs["007"]["120.231.28.114"] = now
	shareglobalUserConfig.activeIPs["WUYOU"] = make(map[string]time.Time)
	shareglobalUserConfig.activeIPs["WUYOU"]["117.136.12.247"] = now
	shareglobalUserConfig.activeIPs["WUYOU"]["125.94.203.13"] = now
	shareglobalUserConfig.activeIPs["hhshljmlq"] = make(map[string]time.Time)
	shareglobalUserConfig.activeIPs["hhshljmlq"]["223.147.195.145"] = now
	shareglobalUserConfig.activeIPs["hotyi"] = make(map[string]time.Time)
	shareglobalUserConfig.activeIPs["hotyi"]["116.28.179.170"] = now
	shareglobalUserConfig.activeIPs["llh203"] = make(map[string]time.Time)
	shareglobalUserConfig.activeIPs["llh203"]["120.230.116.11"] = now
	shareglobalUserConfig.activeIPs["tom"] = make(map[string]time.Time)
	shareglobalUserConfig.activeIPs["tom"]["183.50.96.25"] = now

	// 为 userAccessLog 添加测试数据
	shareglobalUserConfig.userAccessLog["hotyi"] = &Accesslog{
		Entries: []*AccessEntry{
			{IP: "116.28.179.170", Time: now.Add(-5 * time.Minute)},
			{IP: "116.28.179.170", Time: now.Add(-10 * time.Minute)},
			{IP: "116.28.179.170", Time: now.Add(-15 * time.Minute)},
		},
	}
	shareglobalUserConfig.userAccessLog["007"] = &Accesslog{
		Entries: []*AccessEntry{
			{IP: "120.231.28.114", Time: now.Add(-2 * time.Minute)},
			{IP: "120.231.28.114", Time: now.Add(-7 * time.Minute)},
		},
	}
	shareglobalUserConfig.userAccessLog["WUYOU"] = &Accesslog{
		Entries: []*AccessEntry{
			{IP: "117.136.12.247", Time: now.Add(-3 * time.Minute)},
			{IP: "125.94.203.13", Time: now.Add(-8 * time.Minute)},
		},
	}

	shareglobalUserConfig.mu.Unlock()
} //*/

// 定义公共的路径前缀
const basePath = "/etc/caddy/"

/*const basePath = "/Users/hotyi/GolandProjects/caddy_forwardproxy/forwardproxy/"
const CaddyBasePath = "/Users/hotyi/GolandProjects/caddy_forwardproxy/" //*/

const (
	DBDateBaseForUser = basePath + "databases/user_database.hotyi"
	DBDateBaseForLog  = basePath + "databases/log_database.hotyi"
	TamplesForAdmin   = basePath + "templates/admin/*.html"
	TamplesForUser    = basePath + "templates/user/*.html"
	CaddyfilePath     = basePath + "Caddyfile"
	StaticPath        = basePath + "static"
	configPath        = basePath + "config.yaml"
)

// 路径检查函数
func ensurePathExist() error {
	paths := []string{
		filepath.Dir(DBDateBaseForUser),
		filepath.Dir(DBDateBaseForLog),
		filepath.Dir(configPath),
		StaticPath,
	}

	for _, path := range paths {
		if err := os.MkdirAll(path, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %v", path, err)
		}
	}
	return nil
}

func (h *Handler) updateUserTraffic(count int64, username, targetIP, targetHost, targetPath, userAgent string) {

	// 提取 IP 地址部分
	ipAddress := strings.Split(targetIP, ":")[0]

	//定义流量阈值,单位为字节
	//trafficThreshold := int64(24576) //24kb
	h.globalUserConfig.mu.Lock()
	h.globalUserConfig.userTraffic[username] += count

	if h.userManager.config.UserTrafficCheckLevel >= 3 {
		h.globalUserConfig.currentMonthTraffic[username] += count
	}

	if count > h.userManager.config.TrafficThreshold {
		accessLog := h.globalUserConfig.userAccessLog[username]
		if accessLog == nil {
			accessLog = &Accesslog{Entries: make([]*AccessEntry, h.userManager.config.AccessLogSize)} //30个最近ip
			h.globalUserConfig.userAccessLog[username] = accessLog
		}

		// 检查 targetHost 是否为 IP 地址
		if targetHost != "" && net.ParseIP(targetHost) == nil {
			//检查是否存在
			existingEntry := findEntryByHost(accessLog.Entries, targetHost)
			if existingEntry != nil {
				//如果存在,更新时间
				existingEntry.Time = time.Now()
			} else {
				entry := &AccessEntry{
					Time:      time.Now(),
					IP:        ipAddress,
					Host:      targetHost,
					Path:      targetPath,
					UserAgent: userAgent,
				}
				//将新记录添加到访问日志中
				accessLog.Entries[accessLog.index] = entry
				accessLog.index = (accessLog.index + 1) % len(accessLog.Entries)
			}
		}
	}
	h.globalUserConfig.mu.Unlock()

	if h.userManager.config.UserTrafficCheckLevel >= 4 {
		if err := h.checkUserTraffic(username); err != nil {
			h.logger.Error("用户流量检查失败:", zap.Error(err))
		}
	}

	//原来的代码,是根据数据大于10K,然后加入
	/*// 提取 IP 地址部分
	ipAddress := strings.Split(targetIP, ":")[0]

	// 定义流量阈值,单位为字节
	trafficThreshold := int64(10240) // 10KB

	// 检查流量是否超过阈值
	if count > trafficThreshold {
		h.globalUserConfig.mu.Lock()
		h.globalUserConfig.userTraffic[username] += count

		accessLog := h.globalUserConfig.userAccessLog[username]
		if accessLog == nil {
			accessLog = &Accesslog{Entries: make([]*AccessEntry, 20)} //3个最近ip.
			h.globalUserConfig.userAccessLog[username] = accessLog
		}

		// 检查 targetIP 是否为空
		if targetIP != "" {
			entry := &AccessEntry{
				Time:      time.Now(),
				IP:        ipAddress,
				Host:      targetHost,
				Path:      targetPath,
				UserAgent: userAgent,
			}
			//将新记录添加到访问日志中
			accessLog.Entries[accessLog.index] = entry
			accessLog.index = (accessLog.index + 1) % len(accessLog.Entries)
		}

		h.globalUserConfig.mu.Unlock()
	}*/
}

func (h *Handler) updateUserTraffic2(count int64, username string) {

	h.globalUserConfig.mu.Lock()
	h.globalUserConfig.userTraffic[username] += count
	if h.userManager.config.UserTrafficCheckLevel >= 3 {
		h.globalUserConfig.currentMonthTraffic[username] += count
	}
	h.globalUserConfig.mu.Unlock()

	// 修改这里，当UserTrafficCheckLevel >= 4时也检查用户流量
	if h.userManager.config.UserTrafficCheckLevel >= 4 {
		if err := h.checkUserTraffic(username); err != nil {
			h.logger.Error("用户流量检查失败:", zap.Error(err))
		}
	}
}

func findEntryByHost(entries []*AccessEntry, targetHost string) *AccessEntry {
	for _, entry := range entries {
		if entry != nil && entry.Host == targetHost {
			return entry
		}
	}
	return nil
}

// ListenForSystemSignals 监听系统信号,并在收到信号后执行清理操作,然后优雅地退出程序.
// 清理操作的超时时间可以通过 cleanupTimeout 参数进行配置
// ListenForSystemSignals 监听系统信号,并在收到信号后执行清理操作,然后优雅地退出程序。
// 清理操作的超时时间可以通过 cleanupTimeout 参数进行配置。
/*func (um *UserManager) ListenForSystemSignals(cleanupTimeout time.Duration) {
	//捕捉系统信号
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

	//在goroutine中等待信号
	go func() {
		sig := <-sigChan
		fmt.Printf("收到信号: %v\n", sig)

		//停止监听信号
		signal.Stop(sigChan)
		close(sigChan)

		fmt.Println("开始清理操作")

		//创建一个WaitGroup来等待所有清理操作完成
		var wg sync.WaitGroup

		//增加一个计数器
		wg.Add(1)

		go func() {
			defer wg.Done()
			cleanupOnce.Do(func() {
				if err := um.performCleanup(); err != nil {
					fmt.Printf("清理操作失败: %v\n", err)
				} else {
					fmt.Println("清理操作完成")
				}
			})
		}()

		// 等待所有清理操作完成,设置超时时间
		done := make(chan struct{})
		go func() {
			wg.Wait()
			close(done)
		}()

		select {
		case <-done:
			fmt.Println("所有清理操作已完成")
		case <-time.After(cleanupTimeout):
			fmt.Println("清理操作超时")
		}

		fmt.Println("程序退出")

		// 确保所有的清理操作都已经执行完毕后再退出程序
		os.Exit(0)
	}()
}*/

// GetUserUserManager 初始化全局Usermanage和routes
func (h *Handler) GetUserUserManager() *UserManager {
	usermanagerOnce.Do(func() {
		var err error
		shareuserManager, err = NewUserManager()
		if err != nil {
			fmt.Println("UserManager初始化失败！", err)
		}

		//注册自定义路由
		routes = append(routes, caddyhttp.Route{
			MatcherSetsRaw: []caddy.ModuleMap{
				{
					"path": caddyconfig.JSON(caddyhttp.MatchPath{
						"/admin/*",
						"/user/*",
						"/static/*",
						"/inviter_register",
						"/register",
						"/userlogin",
						"/clientarea",
					}, nil),
				},
			},
			HandlersRaw: []json.RawMessage{
				caddyconfig.JSONModuleObject(h, "Handler", "", nil),
			},
		})

		//注册系统倾听方法
		//shareuserManager.ListenForSystemSignals(10)
	})
	return shareuserManager
}

//-------------------------------------------------------------------

func loadConfig(filename string) (*Config, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}

	var config Config
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return nil, err
	}

	return &config, nil
}

func saveConfig(filename string, config *Config) error {
	data, err := yaml.Marshal(config)
	if err != nil {
		return err
	}

	err = os.WriteFile(filename, data, 0644)
	if err != nil {
		return err
	}

	return nil
}

func (um *UserManager) ReloadConfig(filename string) error {

	um.caddyfileMu.Lock()
	newConfig, err := loadConfig(filename)
	um.caddyfileMu.Unlock()

	if err != nil {
		return fmt.Errorf("failed to reload config: %v", err)
	}

	um.config = newConfig
	if newConfig.UserTrafficCheckLevel >= 3 {
		if err := LoadMonthlyLimits(); err != nil {
			fmt.Printf("读取月限额失改,ReloadConfig")
		}
	}
	return nil
}

func NewUserManager() (*UserManager, error) {

	//确保必要的路径存在
	if err := ensurePathExist(); err != nil {
		return nil, fmt.Errorf("failed to ensure paths exist: %v", err)
	}

	userDB, err := sql.Open("sqlite3", DBDateBaseForUser)
	if err != nil {
		return nil, err
	}

	_, err = userDB.Exec(`
	CREATE TABLE IF NOT EXISTS users (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	username TEXT UNIQUE,
	password TEXT,
	max_ips INTEGER,
	expiry_date DATETIME,
	email TEXT,
	tags TEXT,
	totaltraffic INTEGER DEFAULT 0,
	yesterday_traffic INTEGER DEFAULT 0,
	today_traffic INTEGER DEFAULT 0,
  	last_month_traffic INTEGER DEFAULT 0,
  	current_month_traffic INTEGER DEFAULT 0,
  	traffic_limit INTEGER DEFAULT 1,
  	monthly_limit INTEGER DEFAULT 53687091200
);`)
	if err != nil {
		return nil, err
	}

	_, err = userDB.Exec(`CREATE TABLE IF NOT EXISTS root_accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT
);INSERT INTO root_accounts (username, password)
	SELECT 'root', '12345678kt'
	WHERE NOT EXISTS (SELECT 1 FROM root_accounts);`)
	if err != nil {
		return nil, err
	}

	_, err = userDB.Exec(`CREATE TABLE IF NOT EXISTS admin_accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT
);INSERT INTO admin_accounts (username, password)
	SELECT 'admin', '12345678kt'
	WHERE NOT EXISTS (SELECT 1 FROM admin_accounts);`)
	if err != nil {
		return nil, err
	}

	_, err = userDB.Exec(`CREATE TABLE IF NOT EXISTS sysinfo (
    port INTEGER,
    domain TEXT,
    isBanWa INTEGER DEFAULT 1,
    VEID INTEGER DEFAULT 0,
    APIKey TEXT
);`)
	if err != nil {
		return nil, err
	}

	_, err = userDB.Exec(`CREATE TABLE IF NOT EXISTS registration_urls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url_title text,
    quantity INTEGER NOT NULL,
    expiry_days INTEGER NOT NULL,
    max_ips INTEGER NOT NULL,
    tags TEXT,
    hmac_code TEXT NOT NULL
);`)
	if err != nil {
		return nil, err
	}

	logDB, err := sql.Open("sqlite3", DBDateBaseForLog)
	if err != nil {
		return nil, err
	}

	_, err = logDB.Exec(`CREATE TABLE IF NOT EXISTS logs (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	time DATETIME,
	action TEXT,
	username TEXT,
	target_username TEXT
)`)
	if err != nil {
		return nil, err
	}

	//定义模板函数
	funcMap := template.FuncMap{
		"IsExpired": func(expiryDate, now time.Time) bool {
			return expiryDate.Before(now)
		},
	}

	tmpl, err := template.New("admin").Funcs(funcMap).ParseGlob(TamplesForAdmin)
	if err != nil {
		return nil, err
	}

	tmpluser, err := template.New("user").ParseGlob(TamplesForUser)
	if err != nil {
		return nil, err
	}

	//初始化会话存储
	store := sessions.NewCookieStore([]byte("something-very-secret"))

	//读取配置文件
	config, err := loadConfig(configPath)
	if err != nil {
		//如果配置文件不存在,创建默认配置文件
		if os.IsNotExist(err) {
			config = &Config{
				TrafficThreshold:      24576,
				AccessLogSize:         5,
				EnableAccessLog:       false,
				MaxTraffic:            536870912000,
				DailyTraffic:          21474836480,
				IPExpiryDuration:      3600,
				UserTrafficCheckLevel: 2,          //用户流量检查的粒度,数值越大越耗资源
				TaskExecutionHours:    1,          //当UserTrafficCHeckLevel为2的时候,本参数生效,表示多少小时内检查一次流量
				TrafficResetHour:      "06:30:30", //北京时间凌晨12点重置时间统计
				MonthlyRestartDay:     -1,         //每月重启的服务器时间日期天数
			}
			err = saveConfig(configPath, config)
			if err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
	}

	return &UserManager{
		userDB:             userDB,
		logDB:              logDB,
		template:           tmpl,
		tmplUser:           tmpluser,
		store:              store,
		config:             config,
		scheduledTaskSetup: false,
	}, nil
}

// 函数用于创建和启动调度器,并添加任务
func (h *Handler) setupScheduledTask() error {
    // 创建调度器，使用系统时区（已在安装时设置为北京时间）
    s, er := gocron.NewScheduler()
    if er != nil {
        fmt.Println("err:", er)
    }

    // 直接使用当前系统时间（已设置为北京时间）
    now := time.Now()
    h.logger.Info("当前系统时间（北京时间）", zap.Time("current_time", now))

    // 解析TrafficResetHour字符串
    var resetHour, resetMinute int  // 删除了 resetSecond
    h.userManager.caddyfileMu.RLock()
    if strings.Contains(h.userManager.config.TrafficResetHour, ":") {
        // 如果是"HH:MM:SS"格式，则解析出时、分
        parts := strings.Split(h.userManager.config.TrafficResetHour, ":")
        resetHour, _ = strconv.Atoi(parts[0])
        resetMinute, _ = strconv.Atoi(parts[1])
        // 删除了秒的解析，因为cron任务不需要秒级精度
    } else {
        // 如果是整数格式，则直接转换为整数
        resetHour, _ = strconv.Atoi(h.userManager.config.TrafficResetHour)
    }
    h.userManager.caddyfileMu.RUnlock()

    // 直接使用解析出的时间，无需时区转换
    hour := resetHour
    minute := resetMinute

    h.logger.Info("定时任务设置", 
        zap.Int("hour", hour), 
        zap.Int("minute", minute),
        zap.String("timezone", "Asia/Shanghai (系统时区)"))

    // 设置每天在指定时间执行任务
    var taskErr error // 声明一个变量用于保存任务执行过程中的错误
    _, err := s.NewJob(
        gocron.CronJob(
            fmt.Sprintf("%02d %02d * * *", minute, hour), // 分钟 小时 * * *
            false,
        ),
        gocron.NewTask(func() error {

            err := h.updateUserTotalTrafficAtomic()
            if err != nil {
                h.logger.Error("更新总流量失败", zap.Error(err))
                taskErr = err
                return err
            }

            if h.userManager.config.UserTrafficCheckLevel < 2 {
                h.updateCaddyfile()
            }
            //等待更新总流量完成后,执行复制和清空操作
            err = h.copyAndResetTodayTraffic()
            if err != nil {
                h.logger.Error("复制和清空今日流量失败", zap.Error(err))
                taskErr = err
            }

            return nil
        }),
    )
    if err != nil {
        h.logger.Error("设置定时任务失败", zap.Error(err))
    }

    //设置N小时执行一次的任务
    if h.userManager.config.UserTrafficCheckLevel == 2 {
        _, err := s.NewJob(
            gocron.CronJob(
                fmt.Sprintf("0 */%02d * * *", h.userManager.config.TaskExecutionHours),
                false,
            ),
            gocron.NewTask(func() error {
                h.logger.Info("开始检查流量任务...")
                err := h.updateUserTotalTrafficAtomic()
                if err != nil {
                    h.logger.Error("更新总流量失败", zap.Error(err))
                    taskErr = err
                    return err
                }
                h.updateCaddyfile()

                return nil
            }),
        )
        if err != nil {
            h.logger.Error("设置N小时执行检查流量任务失败", zap.Error(err))
        }
    }

    // 开始运行调度器
    s.Start()

    if taskErr != nil {
        return taskErr //如taskErr不为nil,则说明任务执行过程中发生了错误,返回该错误
    }
    h.logger.Info("设置任务成功")
    return nil
}

func (h *Handler) updateUserTrafficForUser(username string) error {
	//build the SQL update statement
	updateQuery := "UPDATE users SET totaltraffic = totaltraffic + ?,current_month_traffic = current_month_traffic + ?,today_traffic = today_traffic + ? WHERE username = ?"

	//Prepare the SQL statement
	stmt, err := h.userManager.userDB.Prepare(updateQuery)
	if err != nil {
		h.logger.Error("准备 SQL 语句失败", zap.Error(err))
		return fmt.Errorf("准备 SQL 语句失败:%v", err)
	}
	defer stmt.Close()

	h.globalUserConfig.mu.RLock()
	traffic, exists := h.globalUserConfig.userTraffic[username]
	h.globalUserConfig.mu.RUnlock()

	if !exists {
		h.logger.Warn("用户流量不存在", zap.String("username", username))
		return nil
	}

	if _, err := stmt.Exec(traffic, traffic, traffic, username); err != nil {
		h.logger.Error("更新数据库失败", zap.Error(err))
		return fmt.Errorf("更新数据库失败:%v", err)
	}

	// 不在这里删除用户信息，统一在checkUserTraffic中处理
	//h.globalUserConfig.mu.Lock()
	//delete(h.globalUserConfig.userTraffic, username)
	//h.globalUserConfig.mu.Unlock()

	h.logger.Info("更新用户流量成功,updateUserTrafficForUser", zap.String("username", username))
	return nil
}

// updateUserTotalTrafficAtomic 尝试原子性地更新users 表中的totaltraffic字段
func (h *Handler) updateUserTotalTrafficAtomic() error {
	h.userManager.mu.Lock()
	// 开启事务
	tx, err := h.userManager.userDB.Begin()
	if err != nil {
		h.logger.Error("开启事务失败", zap.Error(err))
		h.userManager.mu.Unlock()
		return fmt.Errorf("开启事务失败: %v", err)
	}

	// 构建更新 SQL 语句
	updateQuery := "UPDATE users SET totaltraffic = totaltraffic + ?,current_month_traffic = current_month_traffic + ?,today_traffic = today_traffic + ? WHERE username = ?"

	// 准备 SQL 语句
	stmt, err := tx.Prepare(updateQuery)
	if err != nil {
		_ = tx.Rollback() // 如果准备失败，回滚事务
		h.logger.Error("准备 SQL 语句失败", zap.Error(err))
		h.userManager.mu.Unlock()
		return fmt.Errorf("准备 SQL 语句失败: %v", err)
	}
	defer func(stmt *sql.Stmt) {
		_ = stmt.Close()
	}(stmt) // 确保在函数返回时关闭语句

	h.globalUserConfig.mu.RLock()
	//遍历 userTraffic 映射
	for username, traffic := range h.globalUserConfig.userTraffic {
		//执行SQL 语句
		if _, err := stmt.Exec(traffic, traffic, traffic, username); err != nil {
			_ = tx.Rollback() //如果更新失败,回滚事务
			h.logger.Error("更新数据库失败", zap.Error(err))
			h.globalUserConfig.mu.RUnlock()
			h.userManager.mu.Unlock()
			return fmt.Errorf("更新数据库失败:%v\n", err)

		}
	}
	h.globalUserConfig.mu.RUnlock()

	//提交事务
	if err := tx.Commit(); err != nil {
		h.logger.Error("提交事务失败", zap.Error(err))
		h.userManager.mu.Unlock()
		return fmt.Errorf("提交事务失败: %v", err)
	}
	h.userManager.mu.Unlock()

	h.globalUserConfig.mu.Lock()
	//事务提交成功后,删除userTraffic中的条目
	for username := range h.globalUserConfig.userTraffic {
		delete(h.globalUserConfig.userTraffic, username)
	}
	for username := range h.globalUserConfig.userAccessLog {
		delete(h.globalUserConfig.userAccessLog, username)
	}
	h.globalUserConfig.mu.Unlock()
	h.logger.Info("更新数据库成功")
	return nil
}

// 更新昨天和上个月的数据
func (h *Handler) copyAndResetTodayTraffic() error {
	h.userManager.mu.Lock()
	tx, err := h.userManager.userDB.Begin()
	if err != nil {
		h.logger.Error("更新当天流量开启事务失败", zap.Error(err))
		h.userManager.mu.Unlock()
		return fmt.Errorf("开启事务失败: %v", err)
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
		h.userManager.mu.Unlock()
	}()

	//将 today_traffic复制到 yesterday_traffic
	_, err = tx.Exec(`
UPDATE users
SET yesterday_traffic = today_traffic;
`)
	if err != nil {
		h.logger.Error("更新 yesterday_traffic 失败", zap.Error(err))
		return fmt.Errorf("更新 yestday_traffic: %v", err)
	}

	/*//将内存中的流量值累加到 current_month_traffic
		_, err = tx.Exec(`
	UPDATE users SET current_month_traffic = current_month_traffic + today_traffic;
	`)
		if err != nil {
			h.logger.Error("更新 current_month_traffic 失败", zap.Error(err))
			return fmt.Errorf("更新 current_month_traffic: %v", err)
		} //*/

	//检查是否是指定的日期
	now := time.Now()
	if now.Day() == h.userManager.config.MonthlyRestartDay {
		//如果是指定日期,则将 current_month_traffic 复制到 last_month_traffic,并清空 current_month_traffic
		_, err = tx.Exec(`
UPDATE users
SET last_month_traffic = current_month_traffic,
    current_month_traffic = 0;
`)
		if err != nil {
			h.logger.Error("更新 last_month_traffic 和 current_month_traffic 失败", zap.Error(err))
			return fmt.Errorf("更新 last_month_traffic 和 current_month_traffic 失败:%v", err)
		}
	}

	//清空today_traffic
	_, err = tx.Exec(`UPDATE users SET today_traffic = 0;`)
	if err != nil {
		h.logger.Error("清空 today_tarffic 失败", zap.Error(err))
		return fmt.Errorf("清空 today_tarffic 失败: %v", err)
	}

	err = tx.Commit()
	if err != nil {
		h.logger.Error("提交事务失败", zap.Error(err))
		return fmt.Errorf("提交事务失败:%v", err)
	}

	h.logger.Info("更新昨天和上个月的数据成功")
	return nil
	//原来的代码.
	/*	//h.userManager.mu.Lock()
			_, err := h.userManager.userDB.Exec(`
		-- 将 today_traffic 复制到 yesterday_traffic
		UPDATE users SET yesterday_traffic = today_traffic;

		-- 将内存中的流量值累加到 current_month_traffic
		UPDATE users SET current_month_traffic = current_month_traffic + today_traffic;

		-- 检查是否是每个月的第一天,并根据条件更新 last_month_traffic 和 current_month_traffic
		UPDATE users
		SET last_month_traffic = CASE WHEN strftime('%d', date('now')) = '01' THEN current_month_traffic ELSE last_month_traffic END,
		    current_month_traffic = CASE WHEN strftime('%d', date('now')) = '01' THEN 0 ELSE current_month_traffic END;

		-- 清空 today_traffic
		UPDATE users SET today_traffic = 0;
		`)
			//h.userManager.mu.Unlock()
			return err    //*/
}

//func (h *Handler) updateUserTotalTraffic() error {
//
//}

func (h *Handler) ServeUserListPage(w http.ResponseWriter, r *http.Request) {

	session, _ := h.userManager.store.Get(r, "session-name")
	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		http.Redirect(w, r, "/admin/login", http.StatusFound)
		return
	}

	//h.userManager.mu.RLock()
	rows, err := h.userManager.userDB.Query("SELECT username,password,max_ips,expiry_date,email,tags,totaltraffic,current_month_traffic,today_traffic,traffic_limit,monthly_limit FROM users ORDER by ID DESC")
	//h.userManager.mu.RUnlock()
	if err != nil {
		http.Error(w, fmt.Sprintf("Error querying databse:%v", err), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type IPInfo struct {
		IP         string    `json:"ip"`
		LastActive time.Time `json:"last_active"`
	}

	// 在函数内创建临时结构体
	type UserListItem struct {
		Username                 string    `json:"username"`
		Password                 string    `json:"password"`
		MaxIPs                   int       `json:"max_ips"`
		ExpiryDate               time.Time `json:"expiry_date"`
		Email                    string    `json:"email"`
		Tags                     string    `json:"tags"`
		TotalTraffic             int64     `json:"total_traffic"`
		CurrentTraffic           int64     `json:"current_traffic"` //今日流量=数据库的+内存中的
		ActiveIPs                []IPInfo  `json:"active_ips"`
		CurrentMonthTraffic      int64     `json:"current_month_traffic"` //当月流量  = 当月流量+内存中的今天流量
		TodayTraffic             int64     `json:"today_traffic"`         //今天流量
		TrafficLimit             int64     `json:"traffic_limit"`         //是否流量控制
		MonthlyLimit             int64     `json:"monthly_limit"`         //流量月限额
		TotalTrafficPercentage   float64   `json:"total_traffic_percentage"`
		CurrentTrafficPercentage float64   `json:"current_traffic_percentage"`
	}

	var userList []UserListItem
	now := time.Now()

	// 预先复制需要的数据，以减少锁的持有时间
	h.globalUserConfig.mu.Lock()

	activeIPsCopy := make(map[string]map[string]time.Time)
	userTrafficCopy := make(map[string]int64)
	for username, ips := range h.globalUserConfig.activeIPs {
		activeIPsCopy[username] = make(map[string]time.Time)
		for ip, lastActive := range ips {
			activeIPsCopy[username][ip] = lastActive
		}
	}
	for username, traffic := range h.globalUserConfig.userTraffic {
		userTrafficCopy[username] = traffic
	}
	h.globalUserConfig.mu.Unlock()

	for rows.Next() {
		var user UserListItem
		err := rows.Scan(&user.Username, &user.Password, &user.MaxIPs, &user.ExpiryDate, &user.Email, &user.Tags, &user.TotalTraffic, &user.CurrentMonthTraffic, &user.TodayTraffic, &user.TrafficLimit, &user.MonthlyLimit)
		if err != nil {
			http.Error(w, fmt.Sprintf("Error scanning database row: %v", err), http.StatusInternalServerError)
			return
		}

		// 使用复制的数据
		if activeIPs, ok := activeIPsCopy[user.Username]; ok {
			for ip, lastActive := range activeIPs {
				user.ActiveIPs = append(user.ActiveIPs, IPInfo{
					IP:         ip,
					LastActive: lastActive,
				})
			}
		}

		if currentTraffic, ok := userTrafficCopy[user.Username]; ok {
			user.CurrentTraffic = currentTraffic + user.TodayTraffic //今日流量等于内存中的流量加上数据库中的今日流量
			user.CurrentMonthTraffic = user.CurrentMonthTraffic + currentTraffic
		}

		// 计算流量百分比（假设最大流量为 500G）
		//maxTraffic := int64(500 * 1024 * 1024 * 1024)  // 500G in bytes
		//usingTraffic := int64(20 * 1024 * 1024 * 1024) // 20G in 每天
		if user.TrafficLimit > 0 && h.userManager.config.UserTrafficCheckLevel >= 3 {
			user.CurrentMonthTraffic = h.globalUserConfig.currentMonthTraffic[user.Username]
			user.TotalTrafficPercentage = float64(user.CurrentMonthTraffic) / float64(user.MonthlyLimit) * 100
		} else if user.TrafficLimit > 0 && h.userManager.config.UserTrafficCheckLevel < 3 {
			user.TotalTrafficPercentage = float64(user.CurrentMonthTraffic) / float64(user.MonthlyLimit) * 100
		} else {
			user.TotalTrafficPercentage = float64(user.CurrentMonthTraffic) / float64(h.userManager.config.MaxTraffic) * 100
		}
		user.CurrentTrafficPercentage = float64(user.CurrentTraffic) / float64(h.userManager.config.DailyTraffic) * 100

		userList = append(userList, user)
	}

	data := struct {
		Users []UserListItem `json:"Users"`
		Now   time.Time      `json:"now"`
	}{
		Users: userList,
		Now:   now,
	}

	err = h.userManager.template.ExecuteTemplate(w, "userlist.html", data)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error rendering template: %v", err), http.StatusInternalServerError)
		return
	}
}

func (h *Handler) ServeAddUserPage(w http.ResponseWriter, r *http.Request) {

	session, _ := h.userManager.store.Get(r, "session-name")
	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		http.Redirect(w, r, "/admin/login", http.StatusFound)
		return
	}

	err := h.userManager.template.ExecuteTemplate(w, "adduser.html", nil)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error rendering template:%v", err), http.StatusInternalServerError)
		return
	}
}

func (h *Handler) ServeEditUserPage(w http.ResponseWriter, r *http.Request) {

	session, _ := h.userManager.store.Get(r, "session-name")
	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		http.Redirect(w, r, "/admin/login", http.StatusFound)
		return
	}

	username := r.URL.Query().Get("username")
	if username == "" {
		http.Error(w, "用户名缺失", http.StatusBadRequest)
		return
	}

	data := struct {
		Username string
	}{
		Username: username,
	}

	err := h.userManager.template.ExecuteTemplate(w, "edituser.html", data)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error rendering template:%v", err), http.StatusInternalServerError)
		return
	}
}

func (h *Handler) ServeLoginPage(w http.ResponseWriter, r *http.Request) {
	err := h.userManager.template.ExecuteTemplate(w, "login.html", nil)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error rendering template:%v", err), http.StatusInternalServerError)
		return
	}
}

func (h *Handler) ServeUserLoginPage(w http.ResponseWriter, r *http.Request) {
	if err := h.userManager.tmplUser.ExecuteTemplate(w, "login.html", nil); err != nil {
		http.Error(w, fmt.Sprintf("Error rendering template:%v", err), http.StatusInternalServerError)
		return
	}
}

func (h *Handler) ServeClientAreaPage(w http.ResponseWriter, r *http.Request) {
	session, _ := h.userManager.store.Get(r, "user-name")
	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		http.Redirect(w, r, "/userlogin", http.StatusFound)
		return
	}
	username, ok := session.Values["username"].(string)
	if !ok {
		http.Redirect(w, r, "/userlogin", http.StatusFound)
		return
	}

	var user struct {
		Username     string
		ExpiryDate   string
		TotalTraffic int64
	}

	//h.userManager.mu.RLock()
	err := h.userManager.userDB.QueryRow("SELECT username,expiry_date,totaltraffic FROM users WHERE username = ?", username).Scan(&user.Username, &user.ExpiryDate, &user.TotalTraffic)
	//h.userManager.mu.RUnlock()
	if err != nil {
		http.Error(w, "Error fetching user data", http.StatusInternalServerError)
		return
	}

	_, nextMonthlyReset := h.calculateResetTimes()

	data := struct {
		Username      string
		ExpiryDate    string
		TotalTraffic  int64
		NextResetTime time.Time
	}{
		Username:      user.Username,
		ExpiryDate:    user.ExpiryDate,
		TotalTraffic:  user.TotalTraffic,
		NextResetTime: nextMonthlyReset,
	}

	err = h.userManager.tmplUser.ExecuteTemplate(w, "clientarea.html", data)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error rendering template:%v", err), http.StatusInternalServerError)
		return
	}
}

func (h *Handler) ServeqrcodePage(w http.ResponseWriter, r *http.Request) {
	err := h.userManager.template.ExecuteTemplate(w, "qrcode.html", nil)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error rendering template:%v", err), http.StatusInternalServerError)
		return
	}
}

func (h *Handler) ServeQrcodePage(w http.ResponseWriter, r *http.Request) {
	err := h.userManager.tmplUser.ExecuteTemplate(w, "qrcode.html", nil)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error rendering template:%v", err), http.StatusInternalServerError)
		return
	}
}

func (h *Handler) ServeSysInfoPage(w http.ResponseWriter, r *http.Request) {

	session, _ := h.userManager.store.Get(r, "session-name")
	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		http.Redirect(w, r, "/admin/login", http.StatusFound)
		return
	}

	err := h.userManager.template.ExecuteTemplate(w, "sysinfo.html", nil)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error rendering template:%v", err), http.StatusInternalServerError)
		return
	}
}

func (h *Handler) ServeViewLogsPage(w http.ResponseWriter, r *http.Request) {
	session, _ := h.userManager.store.Get(r, "session-name")
	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		http.Redirect(w, r, "/admin/login", http.StatusFound)
		return
	}

	//h.userManager.logMu.RLock()
	rows, err := h.userManager.logDB.Query("SELECT time,action,username,target_username FROM logs ORDER BY time DESC")
	//h.userManager.logMu.RUnlock()
	if err != nil {
		http.Error(w, fmt.Sprintf("Error querying logs:%v", err), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var logs []struct {
		Time           string
		Action         string
		Username       string
		TargetUsername string
	}
	for rows.Next() {
		var logEntry struct {
			Time           string
			Action         string
			Username       string
			TargetUsername string
		}
		if err := rows.Scan(&logEntry.Time, &logEntry.Action, &logEntry.Username, &logEntry.TargetUsername); err != nil {
			http.Error(w, fmt.Sprintf("Error scanning logs:%v", err), http.StatusInternalServerError)
			return
		}
		logs = append(logs, logEntry)
	}

	data := struct {
		Logs []struct {
			Time           string
			Action         string
			Username       string
			TargetUsername string
		}
	}{
		Logs: logs,
	}

	err = h.userManager.template.ExecuteTemplate(w, "viewlogs.html", data)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error rendering template:%v", err), http.StatusInternalServerError)
		return
	}

}

// 用户自助注册
func (h *Handler) ServeRegisterPage(w http.ResponseWriter, r *http.Request) {
	act := r.URL.Query().Get("act")

	var expiryDays, maxIPs, quantity int
	var tags string
	if act != "" {
		//h.userManager.mu.RLock()
		err := h.userManager.userDB.QueryRow("SELECT quantity,expiry_days,max_ips,tags FROM registration_urls WHERE hmac_code = ?", act).Scan(&quantity, &expiryDays, &maxIPs, &tags)
		//h.userManager.mu.RUnlock()
		if err != nil {
			http.Error(w, "Invalid registration code / 无效的注册码", http.StatusForbidden)
			return
		}

		if quantity <= 0 {
			http.Error(w, "Registration URL has expired / 注册网址已过期", http.StatusForbidden)
			return
		}
	} else {
		quantity = 1
		expiryDays = -1
		maxIPs = 1
	}

	data := struct {
		Quantity   int
		ExpiryDays int
		MaxIPs     int
		Tags       string
	}{
		Quantity:   quantity,
		ExpiryDays: expiryDays,
		MaxIPs:     maxIPs,
		Tags:       tags,
	}

	h.userManager.tmplUser.ExecuteTemplate(w, "register.html", data)
}

func (h *Handler) ServeInvitePage(w http.ResponseWriter, r *http.Request) {

	session, _ := h.userManager.store.Get(r, "session-name")
	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		http.Redirect(w, r, "/admin/login", http.StatusFound)
		return
	}

	//为了让invite.html支持ffmpeg,生成视频，添加响应头
	w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
	w.Header().Set("Cross-Origin-Embedder-Policy", "require-corp")

	err := h.userManager.template.ExecuteTemplate(w, "invite.html", nil)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error rendering template:%v", err), http.StatusInternalServerError)
		return
	}
}

// respondWithJSON 是一个帮助函数，用于返回JSON响应
func respondWithJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(payload)
}

func (h *Handler) RegisterUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondWithJSON(w, http.StatusMethodNotAllowed, map[string]interface{}{
			"success": false,
			"message": "Invalid request method / 请求方法无效",
		})
		return
	}

	var user struct {
		Username      string `json:"username"`
		Email         string `json:"email"`
		Password      string `json:"password"`
		EffectiveDate string `json:"effective_date"`
		MaxClients    int    `json:"maximum_client"`
		Tags          string `json:"tags"`
		HmacCode      string `json:"hmac_code"`
	}

	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		respondWithJSON(w, http.StatusBadRequest, map[string]interface{}{
			"success": false,
			"message": "Invalid input / 输入无效",
		})
		return
	}

	//检查用户名是否已存在
	var existingUsername string
	//h.userManager.mu.RLock()
	err := h.userManager.userDB.QueryRow("SELECT username FROM users WHERE username = ?", user.Username).Scan(&existingUsername)
	//h.userManager.mu.RUnlock()

	if err == nil {
		respondWithJSON(w, http.StatusConflict, map[string]interface{}{
			"success": false,
			"message": "Username already exists / 用户名已存在",
		})
		return
	} else if err != sql.ErrNoRows {
		respondWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"success": false,
			"message": "Error checking username",
		})
		return
	}

	//h.userManager.mu.Lock()
	//插入新用户
	_, err = h.userManager.userDB.Exec("INSERT INTO users (username,email,password,max_ips,expiry_date,tags) VALUES (?,?,?,?,?,?)",
		user.Username, user.Email, user.Password, user.MaxClients, user.EffectiveDate, user.Tags)
	//h.userManager.mu.Unlock()

	if err != nil {
		respondWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"success": false,
			"message": "Error adding user / 添加用户出错",
		})
		return
	}

	act := user.HmacCode
	if act != "" {
		//h.userManager.mu.Lock()
		//更新registration_urls表中的数量
		_, err = h.userManager.userDB.Exec("UPDATE registration_urls SET quantity = quantity - 1 WHERE hmac_code = ?", act)
		//h.userManager.mu.Unlock()
		if err != nil {
			respondWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
				"success": false,
				"message": "Database Error:" + err.Error(),
			})
			return
		}
	}

	//从 sysinfo表中读取域名和端口号
	var domain string
	var port int
	//h.userManager.mu.RLock()
	err = h.userManager.userDB.QueryRow("SELECT domain,port FROM sysinfo LIMIT 1").Scan(&domain, &port)
	//h.userManager.mu.RUnlock()

	if err != nil {
		respondWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"success": false,
			"message": "Database Error",
		})
		return
	}

	//如果是邀请用户，则更新Caddyfile()
	if act != "" {
		h.updateCaddyfile()

		if h.userManager.config.UserTrafficCheckLevel >= 3 {
			if err := LoadMonthlyLimits(); err != nil {
				h.logger.Error("读取用户限额失败,RegisterUser", zap.Error(err))
			}
		}
	}
	//返回JSON响应
	response := map[string]interface{}{
		"success":  true,
		"username": user.Username,
		"password": user.Password,
		"expiry":   user.EffectiveDate,
		"ips":      user.MaxClients,
		"domain":   domain,
		"port":     port,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)

	//记录log
	logMsg := fmt.Sprintf("用户自助注册，注册码：%s,用户名：%s,期限：%s,IP数:%d,备注：%s\n", act, user.Username, user.EffectiveDate, user.MaxClients, user.Tags)
	if err := h.logActionStr(user.Username, logMsg, user.Username); err != nil {
		h.logger.Error("保存日志失败", zap.Error(err))
	}
}

func generateHMAC(data, hmacKey string) string {
	key := []byte(hmacKey)
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	fullHMAC := hex.EncodeToString(h.Sum(nil))
	return fullHMAC[:9]
}

func (h *Handler) GetRegistrationURLs(w http.ResponseWriter, r *http.Request) {
	//h.userManager.mu.RLock()
	rows, err := h.userManager.userDB.Query("SELECT id,url_title,quantity,expiry_days,max_ips,tags,hmac_code FROM registration_urls order BY id DESC")
	//h.userManager.mu.RUnlock()
	if err != nil {
		http.Error(w, "数据库错误", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var urls []map[string]interface{}
	for rows.Next() {
		var id, quantity, expiryDays, maxIPs int
		var url_title, tags, hmac_code string
		if err := rows.Scan(&id, &url_title, &quantity, &expiryDays, &maxIPs, &tags, &hmac_code); err != nil {
			http.Error(w, "数据库错误", http.StatusInternalServerError)
			return
		}
		urls = append(urls, map[string]interface{}{
			"id":          id,
			"url_title":   url_title,
			"quantity":    quantity,
			"expiry_days": expiryDays,
			"max_ips":     maxIPs,
			"tags":        tags,
			"hmac_code":   hmac_code,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(urls)
}

func (h *Handler) CreateRegistrationURL(w http.ResponseWriter, r *http.Request) {
	var req struct {
		URLTitle   string `json:"url_title"`
		Quantity   int    `json:"quantity"`
		ExpiryDays int    `json:"expiry_days"`
		MaxIPs     int    `json:"max_ips"`
		Tags       string `json:"tags"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	hmacKey := fmt.Sprintf("%d:%d:%d:%s", req.Quantity, req.ExpiryDays, req.MaxIPs, req.Tags)
	hmacCode := generateHMAC(hmacKey, "haoge-hotyi-simtel-yan")

	//h.userManager.mu.Lock()
	_, err := h.userManager.userDB.Exec("INSERT INTO registration_urls (url_title,quantity,expiry_days,max_ips,tags,hmac_code) VALUES (?,?,?,?,?,?)",
		req.URLTitle, req.Quantity, req.ExpiryDays, req.MaxIPs, req.Tags, hmacCode)
	//h.userManager.mu.Unlock()
	if err != nil {
		http.Error(w, "数据库错误", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
	})
}

func (h *Handler) UpdateRegistrationURL(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID         int    `json:"id"`
		URLTitle   string `json:"url_title"`
		Quantity   int    `json:"quantity"`
		ExpiryDays int    `json:"expiry_days"`
		MaxIPs     int    `json:"max_ips"`
		Tags       string `json:"tags"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	hmacKey := fmt.Sprintf("%d:%d:%d:%s", req.Quantity, req.ExpiryDays, req.MaxIPs, req.Tags)
	hmacCode := generateHMAC(hmacKey, "haoge-hotyi-simtel-yan")
	//h.userManager.mu.Lock()
	_, err := h.userManager.userDB.Exec("UPDATE registration_urls SET url_title=?,quantity = ?,expiry_days = ?,max_ips = ?,tags = ?,hmac_code = ? WHERE id = ?",
		req.URLTitle, req.Quantity, req.ExpiryDays, req.MaxIPs, req.Tags, hmacCode, req.ID)
	//h.userManager.mu.Unlock()
	if err != nil {
		http.Error(w, "数据库错误", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
	})
}

func (h *Handler) DeleteRegistrationURL(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	//h.userManager.mu.Lock()
	_, err := h.userManager.userDB.Exec("DELETE FROM registration_urls WHERE id = ?", id)
	//h.userManager.mu.Unlock()

	if err != nil {
		http.Error(w, "数据库错误", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
	})
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	var storedPassword string
	//h.userManager.mu.RLock()
	err := h.userManager.userDB.QueryRow("SELECT password FROM admin_accounts WHERE username = ?", creds.Username).Scan(&storedPassword)
	//h.userManager.mu.RUnlock()
	if err != nil {
		http.Error(w, "用户名或密码错误", http.StatusUnauthorized)
		return
	}

	if storedPassword != creds.Password {
		http.Error(w, "用户名或密码错误", http.StatusUnauthorized)
		return
	}

	session, _ := h.userManager.store.Get(r, "session-name")
	session.Values["authenticated"] = true
	session.Values["username"] = creds.Username
	session.Save(r, w)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
	})
}

func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	session, _ := h.userManager.store.Get(r, "session-name")
	session.Values["authenticated"] = false
	session.Save(r, w)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
	})
}

func (h *Handler) UserLogout(w http.ResponseWriter, r *http.Request) {
	session, _ := h.userManager.store.Get(r, "user-name")
	session.Values["authenticated"] = false
	//delete(session.Values, "username")
	session.Save(r, w)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
	})
}

func (h *Handler) ReStart(w http.ResponseWriter, r *http.Request) {
	//确保请求方法为POST
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	//从数据库中读取veid和apiKey
	var veid int64
	var apikey string
	var isbanwa int
	//h.userManager.mu.RLock()
	err := h.userManager.userDB.QueryRow("SELECT isbanwa,veid,apikey FROM sysinfo LIMIT 1").Scan(&isbanwa, &veid, &apikey)
	//h.userManager.mu.RUnlock()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to query database:%v", err), http.StatusInternalServerError)
		return
	}

	//检查isbanwa 是否为非零
	if isbanwa == 0 {
		http.Error(w, "This server is not configured as a BanWa server", http.StatusBadRequest)
		return
	}
	//https://api.64clouds.com/v1/restart?veid=1849057&api_key=private_IxNkzJ7tIarehxeuebpdhjal
	//搬瓦工API URL
	apiURL := fmt.Sprintf("https://api.64clouds.com/v1/restart?veid=%d&api_key=%s", veid, apikey)

	//发起HTTP GET 请求到搬瓦工 API
	resp, err := http.Get(apiURL)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to contact API:%v", err), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	//检查API响应状态码
	if resp.StatusCode != http.StatusOK {
		http.Error(w, fmt.Sprintf("API returned non-200 status code:%d", resp.StatusCode), http.StatusInternalServerError)
		return
	}

	//解析API响应
	var apiResponse map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&apiResponse); err != nil {
		http.Error(w, fmt.Sprintf("Failed to decode API response:%v", err), http.StatusInternalServerError)
		return
	}

	//构建返回结果
	result := map[string]interface{}{
		"success": apiResponse["error"] == float64(0), //搬瓦工API返回 error为0表示成功
		"message": apiResponse["message"],
	}

	//发送JSON响应
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(result); err != nil {
		http.Error(w, fmt.Sprintf("Failed to encode response:%v", err), http.StatusInternalServerError)
	}
}

func (h *Handler) GetServiceAreaMetrics(w http.ResponseWriter, r *http.Request) {

	session, _ := h.userManager.store.Get(r, "session-name")
	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		http.Redirect(w, r, "/admin/login", http.StatusFound)
		return
	}

	var isbanwa int
	var veid sql.NullInt64
	var apikey sql.NullString

	//从数据库中读取sysinfo
	//h.userManager.mu.RLock()
	err := h.userManager.userDB.QueryRow("SELECT isbanwa,veid,apikey FROM sysinfo LIMIT 1").Scan(&isbanwa, &veid, &apikey)
	//h.userManager.mu.RUnlock()
	if err != nil {
		respondWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"success": false,
			"message": fmt.Sprintf("Error querying sysinfo from database:%v", err),
		})
		return
	}

	//检查是否是搬瓦工服务器
	if isbanwa != 0 {
		if !veid.Valid || !apikey.Valid {
			//如果veid和apikey为空，返回提示
			respondWithJSON(w, http.StatusBadRequest, map[string]interface{}{
				"success": false,
				"message": "veid和apikey为空，请在后台输入",
			})
			return
		}

		//构建API URL
		apiURL := fmt.Sprintf("https://api.64clouds.com/v1/getLiveServiceInfo?veid=%d&api_key=%s", veid.Int64, apikey.String)

		//发起HTTP请求
		resp, err := http.Get(apiURL)
		if err != nil {
			respondWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
				"success": false,
				"message": fmt.Sprintf("Error contacting API:%v", err),
			})
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			respondWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
				"success": false,
				"message": fmt.Sprintf("Error response from API:%v", err),
			})
			return
		}

		//解析JSON响应
		var apiResponse map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&apiResponse); err != nil {
			respondWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
				"success": false,
				"message": fmt.Sprintf("Error decoding API response:%v", err),
			})
			return
		}

		if h.userManager.config.MonthlyRestartDay == -1 {
			paramValue, ok := apiResponse["data_next_reset"]
			if !ok {
				fmt.Printf("Parameter data_next_reset not found in api response")
			} else {
				timestamp, ok := paramValue.(float64)
				if !ok {
					fmt.Printf("Parameter data_next_reset not found in api response")
				} else {

					//将时间戳转换为服务器本地时间
					localtime := time.Unix(int64(timestamp), 0)
					h.userManager.config.MonthlyRestartDay = localtime.Day()

					//将时间戳转换为北京时间
					h.userManager.config.TrafficResetHour = fmt.Sprintf("%02d:%02d:%02d",localtime.Hour(), localtime.Minute(), localtime.Second())

					err = saveConfig(configPath, h.userManager.config)
					if err != nil {
						fmt.Printf("Error saving config:%v", err)
					} else {
						fmt.Printf("MonthlyRestartDay updated to %s and saved to config.yaml", h.userManager.config.TrafficResetHour)
					}
				}

			}
		}

		//返回JSON响应
		w.Header().Set("Content-Type", "application/json")
		respondWithJSON(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"message": apiResponse,
		})
		return
	}
	//TODO:如果不是搬瓦工服务器，
	respondWithJSON(w, http.StatusBadRequest, map[string]interface{}{
		"success": true,
		"message": "This server is not configgured as a BanWa server",
	})
}

func (h *Handler) SaveAPIKey(w http.ResponseWriter, r *http.Request) {

	session, _ := h.userManager.store.Get(r, "session-name")
	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		http.Redirect(w, r, "/admin/login", http.StatusFound)
		return
	}

	var requestData struct {
		Veid   int    `json:"veid"`
		APIKey string `json:"apiKey"`
	}

	//解析请求体中的JSON数据
	err := json.NewDecoder(r.Body).Decode(&requestData)
	if err != nil {
		respondWithJSON(w, http.StatusBadRequest, map[string]interface{}{
			"success": false,
			"message": fmt.Sprintf("Invalid request payload:%v\n", err),
		})
		return
	}

	//h.userManager.mu.Lock()
	//更新数据库中的veid和apikey
	_, err = h.userManager.userDB.Exec("UPDATE sysinfo SET veid = ?,apikey = ? WHERE isbanwa = 1", requestData.Veid, requestData.APIKey)
	//h.userManager.mu.Unlock()
	if err != nil {
		respondWithJSON(w, http.StatusInternalServerError, map[string]interface{}{
			"success": false,
			"message": fmt.Sprintf("Error updating database:%v\n", err),
		})
		return
	}

	//返回成功响应
	// 返回成功响应
	respondWithJSON(w, http.StatusOK, map[string]interface{}{
		"success": true,
	})
}

func (h *Handler) GetUser(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	if username == "" {
		http.Error(w, "用户名缺失", http.StatusBadRequest)
		return
	}

	var user User
	var trafficLimitInt int
	//h.userManager.mu.RLock()
	err := h.userManager.userDB.QueryRow("SELECT username,password,email,tags,expiry_date,max_ips,traffic_limit,monthly_limit FROM users WHERE username = ?", username).Scan(&user.Username,
		&user.Password, &user.Email, &user.Tags, &user.ExpiryDate, &user.MaxIPs, &trafficLimitInt, &user.MonthlyLimit)
	//h.userManager.mu.RUnlock()
	if err != nil {
		http.Error(w, fmt.Sprintf("Error querying user:%v", err), http.StatusInternalServerError)
		return
	}

	//将traffic_limit从int转换为bool
	user.TrafficLimit = trafficLimitInt == 1

	//Store original values in memory
	editSessions[username] = EditSession{
		OriginalExpiryDate:   user.ExpiryDate.Format("2006-01-02"),
		OriginalMaxIPs:       user.MaxIPs,
		OriginalTags:         user.Tags,
		OriginalTrafficLimit: user.TrafficLimit,
		OriginalMonthlyLimit: user.MonthlyLimit,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)

	/*//构建日志信息
	logMessage := fmt.Sprintf("准备编辑用户:%s,有效期:%s,最大ip数:%d", user.Username, user.ExpiryDate.Format("2006-01-02"), user.MaxIPs)
	if err := h.logAction(r, logMessage, user.Username); err != nil {
		fmt.Fprintf(os.Stderr, "保存日志失败:%v\n", err)
	}*/

}

func (h *Handler) AddUser(w http.ResponseWriter, r *http.Request) {
	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		fmt.Fprintf(os.Stderr, "Error decoding JSON:%v\n", err)
		return
	}
	//fmt.Printf("Received user:%+v\n", user) //debugging line

	//检查用户名是否已经存在
	var existingUsername string
	//h.userManager.mu.RLock()
	err := h.userManager.userDB.QueryRow("SELECT username FROM users WHERE username = ?", user.Username).Scan(&existingUsername)
	//h.userManager.mu.RUnlock()
	if err == nil {
		http.Error(w, "用户名已经存在", http.StatusConflict)
		//fmt.Fprintf(os.Stderr, "用户名已经存在:%s\n", user.Username)
		return
	} else if err != sql.ErrNoRows {
		http.Error(w, "Error checking username: "+err.Error(), http.StatusInternalServerError)
		//fmt.Fprintf(os.Stderr, "Error checking username: %v\n", err)
		return
	}

	//h.userManager.mu.Lock()
	_, err = h.userManager.userDB.Exec("INSERT INTO users (username,password,max_ips,expiry_date,email,tags,traffic_limit,monthly_limit) VALUES (?,?,?,?,?,?,?,?)",
		user.Username, user.Password, user.MaxIPs, user.ExpiryDate, user.Email, user.Tags, user.TrafficLimit, user.MonthlyLimit)
	//h.userManager.mu.Unlock()

	if err != nil {
		http.Error(w, "Error adding user", http.StatusInternalServerError)
		//fmt.Fprintf(os.Stderr, "Error adding user to DB:%v\n", err)
		return
	}

	logMsg := fmt.Sprintf("新增：%s,有效期：%s,最大IP数:%d,备注:%s,限额:%t,额度:%d", user.Username, user.ExpiryDate.Format("2006-01-02"), user.MaxIPs, user.Tags, user.TrafficLimit, user.MonthlyLimit)

	if err := h.logAction(r, logMsg, user.Username); err != nil {
		h.logger.Error("保存日志失败", zap.Error(err))
	}

	//在调用updateCaddyfile之前解锁

	h.updateCaddyfile()

	if h.userManager.config.UserTrafficCheckLevel >= 3 {
		if err := LoadMonthlyLimits(); err != nil {
			h.logger.Error("读取用户限额失败,AddUser", zap.Error(err))
		}
	}

	//重新加锁
	//um.mu.Lock()
	//w.WriteHeader(http.StatusOK)

	//用json返回
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
	})

}

func (h *Handler) DeleteUsers(w http.ResponseWriter, r *http.Request) {

	session, _ := h.userManager.store.Get(r, "session-name")
	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		http.Redirect(w, r, "/admin/login", http.StatusFound)
		return
	}

	var req struct {
		Usernames []string `json:"usernames"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	var logmsg strings.Builder
	logmsg.WriteString("删除用户：")
	//h.userManager.mu.Lock()
	for i, username := range req.Usernames {
		if i > 0 {
			logmsg.WriteString(",") //非第一个用户名前添加逗号
		}
		logmsg.WriteString(fmt.Sprintf("%s", username))
		_, err := h.userManager.userDB.Exec("DELETE FROM users WHERE username = ?", username)
		if err != nil {
			http.Error(w, "Error deleting user", http.StatusInternalServerError)
			//fmt.Fprintf(os.Stderr, "Error deleting user from DB:%v\n", err)
			return
		}
		h.globalUserConfig.mu.Lock()
		delete(h.globalUserConfig.userExpiry, username)
		delete(h.globalUserConfig.userIPLimits, username)
		delete(h.globalUserConfig.activeIPs, username)
		delete(h.globalUserConfig.userTraffic, username)
		delete(h.globalUserConfig.currentMonthTraffic, username)
		delete(h.globalUserConfig.monthlyLimit, username)
		delete(h.globalUserConfig.userAccessLog, username)
		h.globalUserConfig.mu.Unlock()
	}
	//h.userManager.mu.Unlock()

	if err := h.logAction(r, logmsg.String(), "-"); err != nil {
		h.logger.Error("保存日志出错", zap.Error(err))
	}

	h.updateCaddyfile()

	w.Header().Set("Content-Type", "applcation/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
	})
}

func (h *Handler) GetSysInfo(w http.ResponseWriter, r *http.Request) {
	var port int
	var domain string

	// 尝试从数据库中读取 sysinfo
	//h.userManager.mu.RLock()
	err := h.userManager.userDB.QueryRow("SELECT port, domain FROM sysinfo LIMIT 1").Scan(&port, &domain)
	//h.userManager.mu.RUnlock()
	if err == sql.ErrNoRows {
		// 如果数据库中没有记录，读取 Caddyfile
		content, err := os.ReadFile(CaddyfilePath)
		if err != nil {
			http.Error(w, "Error reading Caddyfile", http.StatusInternalServerError)
			return
		}

		// 提取端口号和网址
		re := regexp.MustCompile(`(?m)^:(\d+),\s+(\S+)\s+\{`)
		matches := re.FindStringSubmatch(string(content))
		if len(matches) != 3 {
			http.Error(w, "Could not find port and domain in Caddyfile", http.StatusInternalServerError)
			return
		}

		port, _ = strconv.Atoi(matches[1])
		domain = matches[2]

		// 将信息存入数据库
		//h.userManager.mu.Lock()
		_, err = h.userManager.userDB.Exec("INSERT INTO sysinfo (port, domain) VALUES (?, ?)", port, domain)
		//h.userManager.mu.Unlock()
		if err != nil {
			http.Error(w, "Error saving sysinfo to database", http.StatusInternalServerError)
			return
		}
	} else if err != nil {
		http.Error(w, "Error querying sysinfo from database", http.StatusInternalServerError)
		return
	}

	// 返回 JSON 响应
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"port":    port,
		"domain":  domain,
	})
}

func (h *Handler) UpdateSysInfo(w http.ResponseWriter, r *http.Request) {

	session, _ := h.userManager.store.Get(r, "session-name")
	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		http.Redirect(w, r, "/admin/login", http.StatusFound)
		return
	}

	content, err := os.ReadFile(CaddyfilePath)
	if err != nil {
		http.Error(w, "Error reading Caddyfile", http.StatusInternalServerError)
		return
	}

	// 提取端口号和网址
	re := regexp.MustCompile(`(?m)^:(\d+),\s+(\S+)\s+\{`)
	matches := re.FindStringSubmatch(string(content))
	if len(matches) != 3 {
		http.Error(w, "Could not find port and domain in Caddyfile", http.StatusInternalServerError)
		return
	}

	port, _ := strconv.Atoi(matches[1])
	domain := matches[2]

	//检查sysinfo中是否有一行数据
	var count int
	err = h.userManager.userDB.QueryRow("SELECT COUNT(*) FROM sysinfo").Scan(&count)
	if err != nil {
		http.Error(w, "Error querying sysinfo", http.StatusInternalServerError)
		return
	}

	if count > 0 {
		//更新数据库中的sysinfo记录
		_, err = h.userManager.userDB.Exec("UPDATE sysinfo SET port = ?,domain = ?", port, domain)
		if err != nil {
			http.Error(w, "Error updating sysinfo in database", http.StatusInternalServerError)
			return
		}
	} else {
		//插入新的sysinfo记录
		_, err = h.userManager.userDB.Exec("INSERT INTO sysinfo (port, domain) VALUES (?, ?)", port, domain)
		if err != nil {
			http.Error(w, "Error saving sysinfo to database", http.StatusInternalServerError)
			return
		}
	}

	// 返回 JSON 响应
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"port":    port,
		"domain":  domain,
	})
}

func (h *Handler) EditUser(w http.ResponseWriter, r *http.Request) {
	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		//fmt.Fprintf(os.Stderr, "Error decoding JSON:%v\n", err)
		return
	}

	originalSession, exists := editSessions[user.Username]
	if !exists {
		http.Error(w, "Original data not found", http.StatusInternalServerError)
		return
	}

	//h.userManager.mu.Lock()
	//更新用户数据
	_, err := h.userManager.userDB.Exec("UPDATE users SET password = ?,max_ips = ?,expiry_date = ?,email = ?,tags = ?,traffic_limit = ?,monthly_limit = ? WHERE username = ?",
		user.Password, user.MaxIPs, user.ExpiryDate, user.Email, user.Tags, user.TrafficLimit, user.MonthlyLimit, user.Username)
	//h.userManager.mu.Unlock()

	if err != nil {
		http.Error(w, "Error updating user", http.StatusInternalServerError)

		return
	}

	//Check if changes occurred before logging
	if originalSession.OriginalExpiryDate != user.ExpiryDate.Format("2006-01-02") || originalSession.OriginalMaxIPs != user.MaxIPs ||
		originalSession.OriginalTags != user.Tags || originalSession.OriginalTrafficLimit != user.TrafficLimit ||
		originalSession.OriginalMonthlyLimit != user.MonthlyLimit {
		logMsg := fmt.Sprintf("用户：%s,备注:[%s => %s],有效限:[%s => %s],最大IP数：[%d => %d],限额:[%t => %t],额度:[%d => %d]",
			user.Username,
			originalSession.OriginalTags, user.Tags,
			originalSession.OriginalExpiryDate, user.ExpiryDate.Format("2006-01-02"),
			originalSession.OriginalMaxIPs, user.MaxIPs,
			originalSession.OriginalTrafficLimit, user.TrafficLimit,
			originalSession.OriginalMonthlyLimit, user.MonthlyLimit)

		if err := h.logAction(r, logMsg, user.Username); err != nil {
			h.logger.Error("保存日志失败", zap.Error(err))
		}
	}

	//清除内存中的日志缓存
	delete(editSessions, user.Username)

	h.updateCaddyfile()

	if h.userManager.config.UserTrafficCheckLevel >= 3 {
		if err := LoadMonthlyLimits(); err != nil {
			h.logger.Error("读取用户限额失败", zap.Error(err))
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
	})

}

func (h *Handler) ListUsers(w http.ResponseWriter, r *http.Request) {
	//h.userManager.mu.RLock()
	rows, err := h.userManager.userDB.Query("SELECT username,password,max_ips,expiry_date,email,tags FROM users ORDER by ID DESC")
	//h.userManager.mu.RUnlock()
	if err != nil {
		http.Error(w, "Error listing users", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	users := []User{}
	for rows.Next() {
		var user User
		if err := rows.Scan(&user.Username, &user.Password, &user.MaxIPs, &user.ExpiryDate, &user.Email, &user.Tags); err != nil {
			http.Error(w, "Error scanning user", http.StatusInternalServerError)
			return
		}
		users = append(users, user)
	}
	json.NewEncoder(w).Encode(users)
}

func (h *Handler) logAction(r *http.Request, action, targetUserName string) error {
	session, _ := h.userManager.store.Get(r, "session-name")
	adminUsername, ok := session.Values["username"].(string)
	if !ok {
		return fmt.Errorf("无法获取管理员用户名")
	}
	//h.userManager.logMu.Lock()
	_, err := h.userManager.logDB.Exec("INSERT INTO logs (time,action,username,target_username) VALUES (?,?,?,?)", time.Now().Format("2006-01-02 15:04:05"), action, adminUsername, targetUserName)
	//h.userManager.logMu.Unlock()
	return err
}

func (h *Handler) logActionStr(username, action, targetUsername string) error {
	//h.userManager.logMu.Lock()
	_, err := h.userManager.logDB.Exec("INSERT INTO logs (time,action,username,target_username) VALUES (?,?,?,?)",
		time.Now().Format("2006-01-02 15:04:05"), action, username, targetUsername)
	//h.userManager.logMu.Unlock()
	return err
}

func (h *Handler) updateCaddyfile() {
	// 读取文件内容，避免在整个处理过程中持有锁
	content, err := os.ReadFile(CaddyfilePath)
	if err != nil {
		h.logger.Error("打开CaddyFile失败", zap.Error(err))
		return
	}

	lines := strings.Split(string(content), "\n")

	var proxyStart, proxyEnd int
	foundProxy := false

	// Find the forward_proxy block start and end positions
	for i, line := range lines {
		if strings.Contains(line, "forward_proxy {") {
			proxyStart = i
			foundProxy = true
		}
		if foundProxy && strings.Contains(line, "hide_ip") {
			proxyEnd = i
			break
		}
	}

	//fmt.Fprintf(os.Stderr, "proxyStart: %d, proxyEnd: %d\n", proxyStart, proxyEnd)

	if !foundProxy {
		h.logger.Error("Caddyfile 找不到 forward_proxy 块")
		return
	}

	// Retain the start of forward_proxy block, remove user config lines in between
	newLines := append(lines[:proxyStart+1], lines[proxyEnd:]...)
	//fmt.Fprintf(os.Stderr, "Initial newLines: %v\n", newLines)

	now := time.Now()

	// 查询有效的用户，避免在查询时持有锁
	rows, err := h.userManager.userDB.Query("SELECT username, password, max_ips, expiry_date FROM users WHERE expiry_date > ?  AND (traffic_limit = 0 OR (traffic_limit > 0 AND monthly_limit > current_month_traffic))", now)
	if err != nil {
		h.logger.Error("读取用户出错", zap.Error(err))
		return
	}
	defer rows.Close()

	// 构建新的用户配置行
	var userLines []string
	for rows.Next() {
		var username, password string
		var maxIPs int
		var expiryDate time.Time
		if err := rows.Scan(&username, &password, &maxIPs, &expiryDate); err != nil {
			h.logger.Error("Error scanning user", zap.Error(err))
			return
		}

		newUser := fmt.Sprintf("\t\t\tbasic_auth %s %s %d %s", username, password, maxIPs, expiryDate.Format(time.RFC3339))
		userLines = append(userLines, newUser)
	}

	// 将用户配置行插入到正确位置
	insertPosition := proxyStart + 1
	newLines = append(newLines[:insertPosition], append(userLines, newLines[insertPosition:]...)...)

	newContent := strings.Join(newLines, "\n")

	// 只在写文件时锁定
	h.userManager.caddyfileMu.Lock()
	err = os.WriteFile(CaddyfilePath, []byte(newContent), 0644)
	h.userManager.caddyfileMu.Unlock()

	if err != nil {
		h.logger.Error("Error writing Caddyfile", zap.Error(err))
		return
	}

	// 使用caddy内部API重新加载Caddyfile
	if err := reloadCaddyfile(newContent); err != nil {
		h.logger.Error("failed to reload Caddyfile", zap.Error(err))
		// 添加重试机制
		h.logger.Info("尝试重新加载Caddyfile...")
		time.Sleep(500 * time.Millisecond)
		if err := reloadCaddyfile(newContent); err != nil {
			h.logger.Error("第二次尝试重新加载Caddyfile失败", zap.Error(err))
		} else {
			h.logger.Info("第二次尝试重新加载Caddyfile成功")
		}
	} else {
		h.logger.Info("成功重新加载Caddyfile")
	}
}

// 使用Caddy 内部API 重新加载Caddyfile
func reloadCaddyfile(caddyfileContent string) error {
	//将Caddy 内容转换为JSON格式
	adapter := caddyconfig.GetAdapter("caddyfile")
	configJSON, warnings, err := adapter.Adapt([]byte(caddyfileContent), nil)
	if err != nil {
		return fmt.Errorf("failed to adapt Caddyfile:%v", err)
	}

	if len(warnings) > 0 {
		fmt.Println("Caddyfile 转换警告:")
		for i, warn := range warnings {
			fmt.Printf("  警告 %d: %s\n", i+1, warn)
		}
	}

	// 设置超时时间
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// 尝试加载配置
	err = caddy.Load(configJSON, true)
	if err != nil {
		fmt.Printf("重载配置文件出错: %v\n", err)
		return fmt.Errorf("failed to load config: %v", err)
	}

	// 验证配置是否成功加载
	select {
	case <-ctx.Done():
		if ctx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("重载配置超时")
		}
		return ctx.Err()
	default:
		// 配置成功加载
		return nil
	}
}

func (h *Handler) EditAdminPassword(w http.ResponseWriter, r *http.Request) {
	var input struct {
		CurrentPassword string `json:"currentPassword"`
		NewPassword     string `json:"newPassword"`
	}

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		h.logger.Error("Error decoding JSON", zap.Error(err))
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	// 假设用户名在会话中存储
	session, _ := h.userManager.store.Get(r, "session-name")
	username := session.Values["username"].(string)

	// 验证当前密码
	var storedPassword string
	//h.userManager.mu.RLock()
	err := h.userManager.userDB.QueryRow("SELECT password FROM admin_accounts WHERE username = ?", username).Scan(&storedPassword)
	//h.userManager.mu.RUnlock()
	if err != nil {
		http.Error(w, "Invalid username", http.StatusUnauthorized)
		return
	}

	// 直接对比密码
	if storedPassword != input.CurrentPassword {
		http.Error(w, "旧密码错误", http.StatusUnauthorized)
		return
	}

	// 更新密码
	//h.userManager.mu.Lock()
	_, err = h.userManager.userDB.Exec("UPDATE admin_accounts SET password = ? WHERE username = ?", input.NewPassword, username)
	//h.userManager.mu.Unlock()
	if err != nil {
		http.Error(w, "更新密码出错", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
	})

	logMsg := fmt.Sprintf("管理员 %s 修改了密码", username)
	if err := h.logAction(r, logMsg, username); err != nil {
		h.logger.Error("保存日志失败", zap.Error(err))
	}
}

func (h *Handler) ServeEditAdminPage(w http.ResponseWriter, r *http.Request) {
	session, _ := h.userManager.store.Get(r, "session-name")
	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		http.Redirect(w, r, "/admin/login", http.StatusFound)
		return
	}
	username, ok := session.Values["username"].(string)
	if !ok {
		http.Error(w, "用户名缺失", http.StatusBadRequest)
	}
	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		http.Redirect(w, r, "/admin/login", http.StatusFound)
		return
	}

	if username == "" {
		http.Error(w, "用户名缺失", http.StatusBadRequest)
		return
	}

	data := struct {
		Username string
	}{
		Username: username,
	}

	err := h.userManager.template.ExecuteTemplate(w, "editadmin.html", data)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error rendering template: %v", err), http.StatusInternalServerError)
		return
	}
}

func (h *Handler) UpdateAdminPassword(w http.ResponseWriter, r *http.Request) {
	var update struct {
		ID       int    `json:"id"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	//h.userManager.mu.Lock()
	_, err := h.userManager.userDB.Exec("UPDATE admin_accounts SET password = ? WHERE id = ?", update.Password, update.ID)
	//h.userManager.mu.Unlock()
	if err != nil {
		http.Error(w, "Error updating admin password", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
	})
}

func (h *Handler) UpdateRootPassword(w http.ResponseWriter, r *http.Request) {
	var update struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	h.userManager.mu.Lock()
	_, err := h.userManager.userDB.Exec("UPDATE root_accounts SET password = ? WHERE username = 'root'", update.Password)
	h.userManager.mu.Unlock()
	if err != nil {
		http.Error(w, "Error updating root password", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
	})
}

func (h *Handler) DeleteAdminAccount(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "ID is required", http.StatusBadRequest)
		return
	}

	//h.userManager.mu.Lock()
	_, err := h.userManager.userDB.Exec("DELETE FROM admin_accounts WHERE id = ?", id)
	//h.userManager.mu.Unlock()
	if err != nil {
		http.Error(w, "Error deleting admin account", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
	})
}

func (h *Handler) CreateAdminAccount(w http.ResponseWriter, r *http.Request) {
	var account struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&account); err != nil {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	//h.userManager.mu.Lock()
	_, err := h.userManager.userDB.Exec("INSERT INTO admin_accounts (username, password) VALUES (?, ?)", account.Username, account.Password)
	//h.userManager.mu.Unlock()
	if err != nil {
		http.Error(w, "Error creating admin account", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
	})
}

func (h *Handler) GetAdminAccounts(w http.ResponseWriter, r *http.Request) {
	//h.userManager.mu.RLock()
	rows, err := h.userManager.userDB.Query("SELECT id, username FROM admin_accounts")
	//h.userManager.mu.RUnlock()
	if err != nil {
		http.Error(w, "Error fetching admin accounts", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var accounts []struct {
		ID       int    `json:"id"`
		Username string `json:"username"`
	}
	for rows.Next() {
		var acc struct {
			ID       int    `json:"id"`
			Username string `json:"username"`
		}
		if err := rows.Scan(&acc.ID, &acc.Username); err != nil {
			http.Error(w, "Error scanning admin accounts", http.StatusInternalServerError)
			return
		}
		accounts = append(accounts, acc)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(accounts)
}

func (h *Handler) HandleRootLogin(w http.ResponseWriter, r *http.Request) {
	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	var storedPassword string
	//h.userManager.mu.RLock()
	err := h.userManager.userDB.QueryRow("SELECT password FROM root_accounts WHERE username = ?", creds.Username).Scan(&storedPassword)
	//h.userManager.mu.RUnlock()
	if err != nil || creds.Password != storedPassword {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	session, _ := h.userManager.store.Get(r, "session-root")
	session.Values["authenticated"] = true
	session.Save(r, w)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
	})
}

func (h *Handler) ServeRootPage(w http.ResponseWriter, r *http.Request) {
	session, _ := h.userManager.store.Get(r, "session-root")
	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		http.Redirect(w, r, "/admin/rootlogin", http.StatusFound)
		return
	}

	err := h.userManager.template.ExecuteTemplate(w, "root.html", nil)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error rendering template: %v", err), http.StatusInternalServerError)
		return
	}
}

func (h *Handler) ServeRootLoginPage(w http.ResponseWriter, r *http.Request) {
	err := h.userManager.template.ExecuteTemplate(w, "rootlogin.html", nil)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error rendering template:%v", err), http.StatusInternalServerError)
		return
	}
}

func (h *Handler) calculateResetTimes() (nextDailyReset, nextMonthlyReset time.Time) {
    // 直接使用当前系统时间（已设置为北京时间）
    now := time.Now()

    // 解析TrafficResetHour字符串
    var resetHour, resetMinute, resetSecond int
    h.userManager.caddyfileMu.RLock()
    if strings.Contains(h.userManager.config.TrafficResetHour, ":") {
        // 如果是"HH:MM:SS"格式，则解析出时、分、秒
        parts := strings.Split(h.userManager.config.TrafficResetHour, ":")
        resetHour, _ = strconv.Atoi(parts[0])
        resetMinute, _ = strconv.Atoi(parts[1])
        if len(parts) > 2 {
            resetSecond, _ = strconv.Atoi(parts[2])
        }
    } else {
        // 如果是整数格式，则直接转换为整数
        resetHour, _ = strconv.Atoi(h.userManager.config.TrafficResetHour)
    }
    monthlyRestartDay := h.userManager.config.MonthlyRestartDay
    h.userManager.caddyfileMu.RUnlock()

    // 计算今天的重置时间（系统时区，即北京时间）
    today := now.Truncate(24 * time.Hour)
    todayReset := today.Add(time.Duration(resetHour)*time.Hour + 
        time.Duration(resetMinute)*time.Minute + 
        time.Duration(resetSecond)*time.Second)

    // 计算下次每日重置时间
    if now.Before(todayReset) {
        nextDailyReset = todayReset
    } else {
        nextDailyReset = todayReset.Add(24 * time.Hour)
    }

    // 计算下次月度重置时间
    currentYear, currentMonth, _ := now.Date()
    
    // 尝试当月的重置日期
    monthlyResetThisMonth := time.Date(currentYear, currentMonth, monthlyRestartDay, 
        resetHour, resetMinute, resetSecond, 0, now.Location())
    
    if now.Before(monthlyResetThisMonth) {
        nextMonthlyReset = monthlyResetThisMonth
    } else {
        // 如果当月的重置时间已过，计算下个月的重置时间
        nextMonth := currentMonth + 1
        nextYear := currentYear
        if nextMonth > 12 {
            nextMonth = 1
            nextYear++
        }
        
        // 处理月末日期（如31号在2月不存在的情况）
        nextMonthlyReset = time.Date(nextYear, nextMonth, monthlyRestartDay, 
            resetHour, resetMinute, resetSecond, 0, now.Location())
        
        // 如果日期无效（如2月31日），调整到该月最后一天
        if nextMonthlyReset.Month() != nextMonth {
            // 获取该月的最后一天
            lastDayOfMonth := time.Date(nextYear, nextMonth+1, 0, 
                resetHour, resetMinute, resetSecond, 0, now.Location())
            nextMonthlyReset = lastDayOfMonth
        }
    }

    return nextDailyReset, nextMonthlyReset
}

func (h *Handler) ServeUserConfigPage(w http.ResponseWriter, r *http.Request) {
	session, _ := h.userManager.store.Get(r, "session-name")
	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		http.Redirect(w, r, "/admin/login", http.StatusFound)
		return
	}

	type TrafficData struct {
		TotalTraffic        int64
		LastMonthTraffic    int64
		CurrentMonthTraffic int64
		YesterdayTraffic    int64
		TodayTraffic        int64
		MonthlyLimit        int64
	}

	trafficDetails := make(map[string]map[string]TrafficData)
	//h.userManager.mu.RLock()
	//rows, err := h.userManager.userDB.Query("SELECT username, tags, totaltraffic, last_month_traffic, current_month_traffic, yesterday_traffic,today_traffic,traffic_limit,monthly_limit FROM users ORDER BY totaltraffic DESC")
	rows, err := h.userManager.userDB.Query(`
SELECT 
    username, 
    tags, 
    totaltraffic, 
    last_month_traffic, 
    current_month_traffic, 
    yesterday_traffic,
    today_traffic,
    CASE 
        WHEN traffic_limit = 0 THEN -1 
        ELSE monthly_limit - current_month_traffic 
    END AS monthly_limit
FROM 
    users 
ORDER BY 
    totaltraffic DESC;
`)
	//h.userManager.mu.RUnlock()
	if err != nil {
		http.Error(w, fmt.Sprintf("Error rendering Data:%v", err), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var username, tags string
		var traffic TrafficData
		if err := rows.Scan(&username, &tags, &traffic.TotalTraffic, &traffic.LastMonthTraffic, &traffic.CurrentMonthTraffic,
			&traffic.YesterdayTraffic, &traffic.TodayTraffic, &traffic.MonthlyLimit); err != nil {
			http.Error(w, fmt.Sprintf("Error 2 rendering Data:%v", err), http.StatusInternalServerError)
			return
		}
		if _, ok := trafficDetails[username]; !ok {
			trafficDetails[username] = make(map[string]TrafficData)
		}
		trafficDetails[username][tags] = traffic
	}

	nextDailyRest, nextMonthlyReset := h.calculateResetTimes()

	h.globalUserConfig.mu.RLock()
	data := struct {
		UserExpiry      map[string]time.Time
		UserIPLimits    map[string]int
		ActiveIPs       map[string]map[string]time.Time
		UserTraffic     map[string]int64
		TrafficDetails  map[string]map[string]TrafficData
		UserAccessLog   map[string]*Accesslog
		EnableAccessLog bool
		NextDailyRest   time.Time
		NextResetTime   time.Time
	}{
		UserExpiry:      h.globalUserConfig.userExpiry,
		UserIPLimits:    h.globalUserConfig.userIPLimits,
		ActiveIPs:       h.globalUserConfig.activeIPs,
		UserTraffic:     h.globalUserConfig.userTraffic,
		TrafficDetails:  trafficDetails,
		UserAccessLog:   h.globalUserConfig.userAccessLog,
		EnableAccessLog: h.userManager.config.EnableAccessLog,
		NextDailyRest:   nextDailyRest,
		NextResetTime:   nextMonthlyReset,
	}
	h.globalUserConfig.mu.RUnlock()

	err = h.userManager.template.ExecuteTemplate(w, "userconfig.html", data)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error rendering template: %v", err), http.StatusInternalServerError)
		return
	}

}

func (h *Handler) HandleRootLogout(w http.ResponseWriter, r *http.Request) {
	session, _ := h.userManager.store.Get(r, "session-root")
	session.Values["authenticated"] = false
	session.Save(r, w)

	http.Redirect(w, r, "/admin/rootlogin", http.StatusFound)
}

func (h *Handler) UserLoginAct(w http.ResponseWriter, r *http.Request) {
	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		respondWithJSON(w, http.StatusBadRequest, map[string]interface{}{
			"success": false,
			"message": fmt.Sprintf("错误:%v\n", err),
		})
		return
	}

	var storedPassword string
	//h.userManager.mu.RLock()
	err := h.userManager.userDB.QueryRow("SELECT password FROM users WHERE username = ?", creds.Username).Scan(&storedPassword)
	//h.userManager.mu.RUnlock()
	if err != nil {
		respondWithJSON(w, http.StatusUnauthorized, map[string]interface{}{
			"success": false,
			"message": fmt.Sprintf("错误:%v\n", err),
		})
		return
	}

	if storedPassword != creds.Password {
		respondWithJSON(w, http.StatusUnauthorized, map[string]interface{}{
			"success": false,
			"message": fmt.Sprintf("store:%s\ncreds.pass:%s\n", storedPassword, creds.Password),
		})
		return
	}

	session, _ := h.userManager.store.Get(r, "user-name")
	session.Values["authenticated"] = true
	session.Values["username"] = creds.Username
	_ = session.Save(r, w)

	respondWithJSON(w, http.StatusAccepted, map[string]interface{}{
		"success": true,
	})
	/*w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
	})*/
}

func (h *Handler) UserDetails(w http.ResponseWriter, r *http.Request) {
	session, _ := h.userManager.store.Get(r, "user-name")
	username, ok := session.Values["username"].(string)
	if !ok || !session.Values["authenticated"].(bool) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var user struct {
		Username            string `json:"username"`
		Password            string `json:"password"` // 不输出到 JSON
		MaxIPs              int    `json:"max_ips"`
		ExpiryDate          string `json:"expiry_date"`
		TotalTraffic        int64  `json:"totaltraffic"`
		TrafficLimit        bool   `json:"traffic_limit"`         //是否限额
		CurrentMonthTraffic int64  `json:"current_month_traffic"` //使用了月流量
		MonthlyLimit        int64  `json:"monthly_limit"`         //月限额
		Port                int    `json:"port"`
		Domain              string `json:"domain"`
	}

	//h.userManager.mu.RLock()
	err := h.userManager.userDB.QueryRow("SELECT username,password,max_ips,expiry_date,totaltraffic,current_month_traffic,traffic_limit,monthly_limit FROM users WHERE username = ?", username).Scan(&user.Username, &user.Password, &user.MaxIPs, &user.ExpiryDate, &user.TotalTraffic, &user.CurrentMonthTraffic, &user.TrafficLimit, &user.MonthlyLimit)
	//h.userManager.mu.RUnlock()
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "User not found", http.StatusNotFound)
		} else {
			http.Error(w, fmt.Sprintf("Error fetching user data:%v", err), http.StatusInternalServerError)
		}
		return
	}

	//h.userManager.mu.RLock()
	//查询系统信息
	err = h.userManager.userDB.QueryRow("SELECT port,domain FROM sysinfo LIMIT 1").Scan(&user.Port, &user.Domain)
	//h.userManager.mu.RUnlock()
	if err != nil {
		http.Error(w, fmt.Sprintf("Error fetching system info:%v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(user); err != nil {
		http.Error(w, fmt.Sprintf("Error rendering JSON:%v", err), http.StatusInternalServerError)
		return
	}

}

func (h *Handler) ChangePassWord(w http.ResponseWriter, r *http.Request) {
	// 获取当前会话
	session, _ := h.userManager.store.Get(r, "user-name")
	username, ok := session.Values["username"].(string)
	if !ok || !session.Values["authenticated"].(bool) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// 解析请求体中的新密码
	var request struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	//h.userManager.mu.Lock()
	// 更新数据库中的密码
	_, err := h.userManager.userDB.Exec("UPDATE users SET password = ? WHERE username = ?", request.Password, username)
	//h.userManager.mu.Unlock()
	if err != nil {
		http.Error(w, "Error updating password", http.StatusInternalServerError)
		return
	}

	// 返回成功响应
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
	})
}

func (h *Handler) RestartCaddy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondWithJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "Invalid request method"})
		return
	}

	session, _ := h.userManager.store.Get(r, "session-name")
	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		respondWithJSON(w, http.StatusUnauthorized, map[string]string{"error": "Unauthorized"})
		return
	}

	// 先调用updateUserTotalTrafficAtomic函数
	err := h.updateUserTotalTrafficAtomic()
	if err != nil {
		respondWithJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to update user total traffic"})
		return
	}

	// 调用updateUserTotalTrafficAtomic成功后,发送POST请求到Caddy的/load端点
	resp, err := http.Post("http://localhost:2019/load", "application/json", nil)
	if err != nil {
		respondWithJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "Failed to send restart request to Caddy",
		})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		respondWithJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "Caddy returned non-200 status on restart request",
		})
		return
	}

	respondWithJSON(w, http.StatusOK, map[string]string{"message": "Caddy restarted successfully"})
}

func (h *Handler) SaveTraffic(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondWithJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "Invalid request method"})
		return
	}

	// 检查用户是否已登录
	session, _ := h.userManager.store.Get(r, "session-name")
	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		respondWithJSON(w, http.StatusUnauthorized, map[string]string{"error": "Unauthorized"})
		return
	}

	// 调用updateUserTotalTrafficAtomic函数
	err := h.updateUserTotalTrafficAtomic()
	if err != nil {
		respondWithJSON(w, http.StatusInternalServerError, map[string]string{"error": "Failed to save traffic"})
		return
	}

	respondWithJSON(w, http.StatusOK, map[string]interface{}{"success": true, "message": "Traffic saved successfully"})
}

func (h *Handler) UpgradeSystem(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondWithJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "Invalid request method"})
		return
	}

	session, _ := h.userManager.store.Get(r, "session-name")
	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		respondWithJSON(w, http.StatusUnauthorized, map[string]string{"error": "Unauthorized"})
		return
	}

	// 下载update.sh脚本
	resp, err := http.Get("https://raw.githubusercontent.com/simtelboy/haogezhiming2/main/update.sh")
	if err != nil {
		respondWithJSON(w, http.StatusInternalServerError, map[string]string{"success": "false", "message": "Failed to download update script"})
		return
	}
	defer resp.Body.Close()

	// 创建临时文件来存储脚本
	tmpFile, err := ioutil.TempFile("", "update-*.sh")
	if err != nil {
		respondWithJSON(w, http.StatusInternalServerError, map[string]string{"success": "false", "message": "Failed to create temporary file"})
		return
	}
	defer os.Remove(tmpFile.Name())

	// 将下载的脚本写入临时文件
	_, err = io.Copy(tmpFile, resp.Body)
	if err != nil {
		respondWithJSON(w, http.StatusInternalServerError, map[string]string{"success": "false", "message": "Failed to write update script"})
		return
	}
	tmpFile.Close()

	// 使脚本具有可执行权限
	err = os.Chmod(tmpFile.Name(), 0700)
	if err != nil {
		respondWithJSON(w, http.StatusInternalServerError, map[string]string{"success": "false", "message": "Failed to set execute permission on script"})
		return
	}

	// 执行脚本
	cmd := exec.Command("bash", tmpFile.Name())
	err = cmd.Run()
	if err != nil {
		respondWithJSON(w, http.StatusInternalServerError, map[string]string{"success": "false", "message": "System upgrade failed"})
		return
	}

	respondWithJSON(w, http.StatusOK, map[string]string{"success": "true", "message": "System upgrade started"})
}

func (h *Handler) ReloadConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondWithJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "Invalid request method"})
		return
	}

	session, _ := h.userManager.store.Get(r, "session-name")
	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		respondWithJSON(w, http.StatusUnauthorized, map[string]string{"error": "Unauthorized"})
		return
	}

	err := h.userManager.ReloadConfig(configPath)
	if err != nil {
		respondWithJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	respondWithJSON(w, http.StatusOK, map[string]string{"success": "Config reloaded successfully"})
}

func (h *Handler) LoadConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		respondWithJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "Invalid request method"})
		return
	}

	session, _ := h.userManager.store.Get(r, "session-name")
	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		respondWithJSON(w, http.StatusUnauthorized, map[string]string{"error": "Unauthorized"})
		return
	}

	configData, err := loadConfig(configPath)
	if err != nil {
		respondWithJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	configJSON, jsonErr := json.Marshal(configData)
	if jsonErr != nil {
		respondWithJSON(w, http.StatusInternalServerError, map[string]string{"error": jsonErr.Error()})
		return
	}

	respondWithJSON(w, http.StatusOK, map[string]interface{}{"success": true, "config": string(configJSON)})
}

func (h *Handler) UpdateConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		respondWithJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "Invalid request method"})
		return
	}

	session, _ := h.userManager.store.Get(r, "session-name")
	if auth, ok := session.Values["authenticated"].(bool); !ok || !auth {
		respondWithJSON(w, http.StatusUnauthorized, map[string]string{"error": "Unauthorized"})
		return
	}

	var requestData Config
	if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
		respondWithJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	err := saveConfig(configPath, &requestData)
	if err != nil {
		respondWithJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	err = h.userManager.ReloadConfig(configPath)
	if err != nil {
		respondWithJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	respondWithJSON(w, http.StatusOK, map[string]string{"success": "Config reloaded successfully"})

}

// 如果h.userManager.config.UserTrafficCheckLevel >= 4 则调用此函数,采用最高级别的流量计算方式
func (h *Handler) checkUserTraffic(username string) error {
	// Check monthly traffic
	h.globalUserConfig.mu.RLock()
	exceedsLimit := false
	if traffic, exists := h.globalUserConfig.monthlyLimit[username]; exists {
		if h.globalUserConfig.currentMonthTraffic[username] > traffic {
			exceedsLimit = true
		}
	}
	h.globalUserConfig.mu.RUnlock()

	if exceedsLimit {
		if err := h.updateUserTrafficForUser(username); err != nil {
			h.logger.Error("保存用户流量到数据库失败,CheckCredentials:", zap.Error(err))
		}
		h.logger.Info("流量超额:", zap.String("用户:", username))
		h.updateCaddyfile()
		h.globalUserConfig.mu.Lock()
		delete(h.globalUserConfig.monthlyLimit, username)
		delete(h.globalUserConfig.currentMonthTraffic, username)
		delete(h.globalUserConfig.userExpiry, username)
		delete(h.globalUserConfig.userIPLimits, username)
		delete(h.globalUserConfig.activeIPs, username)
		delete(h.globalUserConfig.userAccessLog, username)
		h.globalUserConfig.mu.Unlock()

		return fmt.Errorf("用户流量超出限额: %s", username)
	}
	return nil
}

// 给UserManager新增一个ServeHTTP
func (h *Handler) RouteRequest(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	switch {
	case strings.HasPrefix(path, "/admin/add_user"):
		h.AddUser(w, r)
	case strings.HasPrefix(path, "/admin/adduser"):
		h.ServeAddUserPage(w, r)
	case strings.HasPrefix(path, "/admin/get_user"):
		h.GetUser(w, r)
	case strings.HasPrefix(path, "/admin/edituser"):
		h.ServeEditUserPage(w, r)
	case strings.HasPrefix(path, "/admin/delete_users"):
		h.DeleteUsers(w, r)
	case strings.HasPrefix(path, "/admin/edit_user"):
		h.EditUser(w, r)
	case strings.HasPrefix(path, "/admin/list_users"):
		h.ListUsers(w, r)
	case strings.HasPrefix(path, "/admin/userlist"):
		h.ServeUserListPage(w, r)
	case strings.HasPrefix(path, "/admin/admin_login"):
		h.Login(w, r)
	case strings.HasPrefix(path, "/admin/sysinfo"):
		h.ServeSysInfoPage(w, r)
	case strings.HasPrefix(path, "/admin/get_sysinfo"):
		h.GetSysInfo(w, r)
	case strings.HasPrefix(path, "/admin/getServiceAreaMetrics"):
		h.GetServiceAreaMetrics(w, r)
	case strings.HasPrefix(path, "/admin/saveapikey"):
		h.SaveAPIKey(w, r)
	case strings.HasPrefix(path, "/admin/update_sysinfo"):
		h.UpdateSysInfo(w, r)
	case strings.HasPrefix(path, "/admin/login"):
		h.ServeLoginPage(w, r)
	case strings.HasPrefix(path, "/admin/logout"):
		h.Logout(w, r)
	case strings.HasPrefix(path, "/admin/viewlogs"):
		h.ServeViewLogsPage(w, r)
	case strings.HasPrefix(path, "/admin/qrcode"):
		h.ServeqrcodePage(w, r)
	case strings.HasPrefix(path, "/register"):
		h.ServeRegisterPage(w, r)
	case strings.HasPrefix(path, "/inviter_register"):
		h.RegisterUser(w, r)
	case strings.HasPrefix(path, "/qrcode"):
		h.ServeQrcodePage(w, r)
	case strings.HasPrefix(path, "/admin/invite"):
		h.ServeInvitePage(w, r)
	case strings.HasPrefix(path, "/admin/get_registration_urls"):
		h.GetRegistrationURLs(w, r)
	case strings.HasPrefix(path, "/admin/create_registration_url"):
		h.CreateRegistrationURL(w, r)
	case strings.HasPrefix(path, "/admin/update_registration_url"):
		h.UpdateRegistrationURL(w, r)
	case strings.HasPrefix(path, "/admin/delete_registration_url"):
		h.DeleteRegistrationURL(w, r)
	case strings.HasPrefix(path, "/admin/editadmin"):
		h.ServeEditAdminPage(w, r)
	case strings.HasPrefix(path, "/admin/update_password"):
		h.EditAdminPassword(w, r)
	case strings.HasPrefix(path, "/admin/super"):
		h.ServeRootPage(w, r)
	case strings.HasPrefix(path, "/admin/rootlogin"):
		h.ServeRootLoginPage(w, r)
	case strings.HasPrefix(path, "/admin/root_login"):
		h.HandleRootLogin(w, r)
	case strings.HasPrefix(path, "/admin/get_admin_accounts"):
		h.GetAdminAccounts(w, r)
	case strings.HasPrefix(path, "/admin/create_admin_account"):
		h.CreateAdminAccount(w, r)
	case strings.HasPrefix(path, "/admin/delete_admin_account"):
		h.DeleteAdminAccount(w, r)
	case strings.HasPrefix(path, "/admin/update_admin_password"):
		h.UpdateAdminPassword(w, r)
	case strings.HasPrefix(path, "/admin/update_root_password"):
		h.UpdateRootPassword(w, r)
	case strings.HasPrefix(path, "/admin/rootlogout"):
		h.HandleRootLogout(w, r)
	case strings.HasPrefix(path, "/admin/userconfig"):
		h.ServeUserConfigPage(w, r)
	case strings.HasPrefix(path, "/user/login_act"):
		h.UserLoginAct(w, r)
	case strings.HasPrefix(path, "/userlogin"):
		h.ServeUserLoginPage(w, r)
	case strings.HasPrefix(path, "/clientarea"):
		h.ServeClientAreaPage(w, r)
	case strings.HasPrefix(path, "/user/userdetails"):
		h.UserDetails(w, r)
	case strings.HasPrefix(path, "/user/changepassword"):
		h.ChangePassWord(w, r)
	case strings.HasPrefix(path, "/user/userlogout"):
		h.UserLogout(w, r)
	case strings.HasPrefix(path, "/admin/restart"):
		h.ReStart(w, r)
	case strings.HasPrefix(path, "/admin/restartcaddy"):
		h.RestartCaddy(w, r)
	case strings.HasPrefix(path, "/admin/savetraffic"):
		h.SaveTraffic(w, r)
	case strings.HasPrefix(path, "/admin/upgrade"):
		h.UpgradeSystem(w, r)
	case strings.HasPrefix(path, "/admin/reloadconfig"):
		h.ReloadConfig(w, r)
	case strings.HasPrefix(path, "/admin/loadconfig"):
		h.LoadConfig(w, r)
	case strings.HasPrefix(path, "/admin/updateconfig"):
		h.UpdateConfig(w, r)
	case strings.HasPrefix(path, "/static/"):
		http.StripPrefix("/static/", http.FileServer(http.Dir(StaticPath))).ServeHTTP(w, r)
	default:
		return
	}
}
