package forwardproxy

import (
	"archive/zip"
	_ "embed"
	"fmt"
	"io"
	"os"
	"os/exec" 
	"path/filepath"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2/cmd/caddycmd"  // 注意这个导入路径
	"github.com/spf13/cobra"
)

//go:embed embedded_files.zip
var embeddedFiles []byte

const (
	flagFilePath = "/etc/caddy/.caddy_initialized"
	extractPath  = "/etc/caddy"
)

func init() {

	// 首次运行检查和文件解压逻辑
    if isFirstRun() {
        fmt.Println("检测到首次运行，正在释出系统文件...")
        if err := extractEmbeddedFiles(); err != nil {
            fmt.Printf("警告:释出系统文件失败: %v\n", err)
        } else {
            fmt.Println("成功解压嵌入文件到 /etc/caddy/")
            
            if err := runInstallScript(); err != nil {
                fmt.Printf("警告: 无法准备安装过程: %v\n", err)
            } else {
                fmt.Println("安装脚本已准备就绪，请运行: sudo /etc/caddy/install.sh")
                fmt.Println("或者使用新的安装命令: sudo caddy install")
            }
        }
    }
	
    // 注册自定义命令
    caddycmd.RegisterCommand(caddycmd.Command{
        Name:  "install",
        Usage: "[--interactive]",
        Short: "安装和配置 天神之眼服务",
        Long: `安装和配置  天神之眼服务，包含交互式设置向导。

此命令将执行以下操作：
1. 解压嵌入的配置文件
2. 运行交互式设置向导
3. 生成系统服务文件
4. 配置并启动服务`,
        CobraFunc: func(cmd *cobra.Command) {
            cmd.Flags().Bool("interactive", false, "强制交互模式")
            cmd.RunE = func(cmd *cobra.Command, args []string) error {
                interactive, _ := cmd.Flags().GetBool("interactive")
                return runInstallCommand(interactive)
            }
        },
    })
}


func runInstallCommand(forceInteractive bool) error {
    fmt.Println("🚀 开始安装 天神之眼服务...")
    
    // 1. 检查权限
    if os.Geteuid() != 0 {
        fmt.Println("❌ 需要root权限，请使用: sudo caddy install")
        return fmt.Errorf("需要root权限")
    }

    // 2. 确保文件已解压
    fmt.Println("📦 正在释出配置文件...")
    if err := extractEmbeddedFiles(); err != nil {
        fmt.Printf("❌ 释出文件失败: %v\n", err)
        return err
    }
    fmt.Println("✅ 配置文件释出完成")

    // 3. 检查安装脚本是否存在
    scriptPath := "/etc/caddy/install.sh"
    if _, err := os.Stat(scriptPath); os.IsNotExist(err) {
        fmt.Printf("❌ 缺少配置: %s\n", scriptPath)
        return fmt.Errorf("配置文件不存在: %s", scriptPath)
    }

    // 4. 设置脚本权限
    fmt.Println("🔧 设置权限...")
    if err := os.Chmod(scriptPath, 0755); err != nil {
        fmt.Printf("❌ 设置权限失败: %v\n", err)
        return fmt.Errorf("设置权限失败: %v", err)
    }

    // 5. 运行安装脚本
    fmt.Println("⚙️  正在运行安装...")
    fmt.Println("📝 请按照提示输入配置信息...")
    
    cmd := exec.Command("/bin/bash", scriptPath)
    cmd.Stdout = os.Stdout
    cmd.Stderr = os.Stderr
    cmd.Stdin = os.Stdin

    // 6. 执行并处理错误
    if err := cmd.Run(); err != nil {
        // 检查是否是退出码错误
        if exitError, ok := err.(*exec.ExitError); ok {
            exitCode := exitError.ExitCode()
            fmt.Printf("❌ 安装执行失败，退出码: %d\n", exitCode)
            
            // 根据退出码给出不同的提示
            switch exitCode {
            case 1:
                fmt.Println("💡 提示: 可能是配置输入有误，请检查域名、邮箱等信息")
            case 2:
                fmt.Println("💡 提示: 可能是系统权限问题，请确保以root权限运行")
            case 130:
                fmt.Println("💡 提示: 安装被用户中断 (Ctrl+C)")
                return fmt.Errorf("安装被用户中断")
            default:
                fmt.Println("💡 提示: 安装过程中遇到未知错误")
            }
            
            return fmt.Errorf("安装过程执行失败，退出码: %d", exitCode)
        }
        
        fmt.Printf("❌ 安装失败: %v\n", err)
        return fmt.Errorf("安装失败: %v", err)
    }

    // 7. 验证安装结果
    fmt.Println("🔍 验证安装结果...")
    if err := verifyInstallation(); err != nil {
        fmt.Printf("⚠️  安装可能不完整: %v\n", err)
        fmt.Println("💡 建议手动检查服务状态: systemctl status caddy")
        // 不返回错误，因为主要安装可能已经完成
    }

    fmt.Println("🎉 安装完成！")
    fmt.Println("📋 后续步骤:")
    fmt.Println("   1. 检查服务状态: systemctl status caddy")
    fmt.Println("   2. 查看日志: journalctl -u caddy -f")
    fmt.Println("   3. 访问管理界面进行进一步配置")
    
    return nil
}

// 验证安装结果
func verifyInstallation() error {
    // 检查服务文件是否存在
    if _, err := os.Stat("/etc/systemd/system/caddy.service"); os.IsNotExist(err) {
        return fmt.Errorf("systemd服务文件不存在")
    }

    // 检查Caddyfile是否存在
    if _, err := os.Stat("/etc/caddy/Caddyfile"); os.IsNotExist(err) {
        return fmt.Errorf("Caddyfile配置文件不存在")
    }

    // 可以添加更多检查...
    return nil
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
	_, err = flagFile.WriteString(fmt.Sprintf("Caddy files extracted at: %s\n", time.Now().Format("2006-01-02 15:04:05")))
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


