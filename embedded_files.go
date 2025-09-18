package forwardproxy

import (
	"archive/zip"
	_ "embed"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	caddycmd "github.com/caddyserver/caddy/v2/cmd"
)

//go:embed embedded_files.zip
var embeddedFiles []byte

const (
	flagFilePath = "/etc/caddy/.caddy_initialized"
	extractPath  = "/etc/caddy"
)

// init 函数在包加载时就执行文件解压
func init() {
	// 在模块初始化时就执行文件解压
	if isFirstRun() {
		fmt.Println("检测到首次运行，正在释出系统文件...")
		if err := extractEmbeddedFiles(); err != nil {
			fmt.Printf("警告: 释出系统文件失败: %v\n", err)
		} else {
			fmt.Println("成功释出系统文件到 /etc/caddy/")

			// 解压成功后，设置安装脚本权限并提示用户
			if err := runInstallScript(); err != nil {
				fmt.Printf("警告: 无法指定安装脚本权限，请手动输入：chmod +x /etc/caddy/install.sh : %v\n", err)
			} else {
				fmt.Println("安装脚本已准备就绪，请运行: sudo /etc/caddy/install.sh")
				fmt.Println("或者使用新的安装命令: sudo caddy install")
			}
		}
	}

	// 注册自定义命令
	caddycmd.RegisterCommand(caddycmd.Command{
		Name:  "install",
		Func:  cmdInstall,
		Usage: "[--interactive]",
		Short: "安装和配置 天神之眼服务",
		Flags: func() *flag.FlagSet {
			fs := flag.NewFlagSet("install", flag.ExitOnError)
			fs.Bool("interactive", false, "强制交互模式")
			return fs
		}(),
	})
}

// extractEmbeddedFiles 解压嵌入的zip文件到指定目录
func extractEmbeddedFiles() error {
	// 检查标志文件是否存在
	if _, err := os.Stat(flagFilePath); err == nil {
		// 标志文件存在，说明已经解压过了
		return nil
	}

	// 创建目标目录
	if err := os.MkdirAll(extractPath, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %v", extractPath, err)
	}

	// 创建zip reader
	zipReader, err := zip.NewReader(strings.NewReader(string(embeddedFiles)), int64(len(embeddedFiles)))
	if err != nil {
		return fmt.Errorf("failed to create zip reader: %v", err)
	}

	// 解压文件
	for _, file := range zipReader.File {
		// 构建完整路径
		fullPath := filepath.Join(extractPath, file.Name)

		// 确保路径安全（防止路径遍历攻击）
		if !strings.HasPrefix(fullPath, extractPath) {
			continue
		}

		if file.FileInfo().IsDir() {
			// 创建目录
			if err := os.MkdirAll(fullPath, file.FileInfo().Mode()); err != nil {
				return fmt.Errorf("failed to create directory %s: %v", fullPath, err)
			}
			continue
		}

		// 创建文件
		if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
			return fmt.Errorf("failed to create parent directory for %s: %v", fullPath, err)
		}

		// 打开zip文件中的文件
		rc, err := file.Open()
		if err != nil {
			return fmt.Errorf("failed to open file in zip: %v", err)
		}

		// 创建目标文件
		outFile, err := os.OpenFile(fullPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, file.FileInfo().Mode())
		if err != nil {
			rc.Close()
			return fmt.Errorf("failed to create file %s: %v", fullPath, err)
		}

		// 复制文件内容
		_, err = io.Copy(outFile, rc)
		rc.Close()
		outFile.Close()

		if err != nil {
			return fmt.Errorf("failed to write file %s: %v", fullPath, err)
		}
	}

	// 创建标志文件
	flagFile, err := os.Create(flagFilePath)
	if err != nil {
		return fmt.Errorf("failed to create flag file: %v", err)
	}
	defer flagFile.Close()

	// 写入一些信息到标志文件
	_, err = fmt.Fprintf(flagFile, "Caddy files extracted at: %s\n", time.Now().Format("2006-01-02 15:04:05"))
	if err != nil {
		return fmt.Errorf("failed to write to flag file: %v", err)
	}

	return nil
}

// isFirstRun 检查是否是首次运行
func isFirstRun() bool {
	_, err := os.Stat(flagFilePath)
	return os.IsNotExist(err)
}

// runInstallScript 运行安装脚本
func runInstallScript() error {
	scriptPath := "/etc/caddy/install.sh"

	// 检查脚本是否存在
	if _, err := os.Stat(scriptPath); os.IsNotExist(err) {
		return fmt.Errorf("install script not found at %s", scriptPath)
	}

	// 设置脚本为可执行
	if err := os.Chmod(scriptPath, 0755); err != nil {
		return fmt.Errorf("failed to make script executable: %v", err)
	}

	return nil
}

// cmdInstall 处理 install 命令
func cmdInstall(flags caddycmd.Flags) (int, error) {
	interactive := flags.Bool("interactive")

	fmt.Println("🚀 开始安装 天神之眼服务...")

	// 确保文件已解压
	if isFirstRun() {
		fmt.Println("📦 正在释出配置文件...")
		if err := extractEmbeddedFiles(); err != nil {
			fmt.Printf("❌ 释出配置文件失败: %v\n", err)
			return 1, err
		}
		fmt.Println("✅ 配置文件释出完成")
	}

	// 设置脚本权限
	fmt.Println("🔧 设置权限...")
	if err := runInstallScript(); err != nil {
		fmt.Printf("❌ 设置权限失败: %v\n", err)
		return 1, err
	}

	// 运行安装脚本
	fmt.Println("⚙️  正在运行安装脚本...")
	scriptPath := "/etc/caddy/install.sh"

	var args []string
	args = append(args, scriptPath)
	if interactive {
		args = append(args, "--interactive")
	}

	// 直接执行安装脚本
	cmd := exec.Command("/bin/bash", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	if err := cmd.Run(); err != nil {
		fmt.Printf("❌ 安装脚本执行失败: %v\n", err)
		fmt.Printf("� 您也可以手动运行: sudo %s\n", scriptPath)
		return 1, err
	}

	fmt.Println("✅ 安装完成！")
	return 0, nil
}
