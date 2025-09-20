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

// init 函数只注册命令
func init() {
	// 注册自定义命令
	caddycmd.RegisterCommand(caddycmd.Command{
		Name:  "install",
		Func:  cmdInstall,
		Usage: "[--interactive]",
		Short: "安装和配置天神之眼服务,软件作者:hotyi",
		Flags: func() *flag.FlagSet {
			fs := flag.NewFlagSet("install", flag.ExitOnError)
			fs.Bool("interactive", false, "强制交互模式")
			return fs
		}(),
	})


	// 新增：更新命令
    caddycmd.RegisterCommand(caddycmd.Command{
        Name:  "update",
        Func:  cmdUpdate,
        Usage: "",
        Short: "更新天神之眼到最新版本",
    })

	 // 新增：备份命令
    caddycmd.RegisterCommand(caddycmd.Command{
        Name:  "backup",
        Func:  cmdBackup,
        Usage: "",
        Short: "备份天神之眼配置数据,软件作者:hotyi",
    })

	// 新增：恢复命令
    caddycmd.RegisterCommand(caddycmd.Command{
        Name:  "restore",
        Func:  cmdRestore,
        Usage: "",
        Short: "恢复天神之眼配置数据,软件作者:hotyi",
    })

    // 新增：卸载命令
    caddycmd.RegisterCommand(caddycmd.Command{
        Name:  "uninstall",
        Func:  cmdUninstall,
        Usage: "",
        Short: "卸载天神之眼服务,软件作者:hotyi",
    })

// 新增：自动更新设置命令
caddycmd.RegisterCommand(caddycmd.Command{
    Name:  "autoupdate",
    Func:  cmdAutoUpdate,
    Usage: "[enable|disable|status]",
    Short: "管理天神之眼自动更新设置,软件作者:hotyi",
    Flags: func() *flag.FlagSet {
        fs := flag.NewFlagSet("autoupdate", flag.ExitOnError)
        fs.Bool("enable", false, "启用自动更新")
        fs.Bool("disable", false, "禁用自动更新")
        fs.Bool("status", false, "查看状态")
        return fs
    }(),
})
	
// 新增：更新脚本命令
caddycmd.RegisterCommand(caddycmd.Command{
    Name:  "update-scripts",
    Func:  cmdUpdateScripts,
    Usage: "[--force]",
    Short: "更新天神之眼功能配置文件,软件作者:hotyi",
    Flags: func() *flag.FlagSet {
        fs := flag.NewFlagSet("update-scripts", flag.ExitOnError)
        fs.Bool("force", false, "强制更新所有功能配置文件")
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

	fmt.Println("🚀 开始安装天神之眼服务...")

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
	fmt.Println("⚙️  正在执行安装...")
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
		fmt.Printf("❌ 安装执行失败: %v\n", err)
		fmt.Printf("� 您也可以手动运行: sudo %s\n", scriptPath)
		return 1, err
	}

	fmt.Println("✅ 安装完成！🎉🎉")
	return 0, nil
}


// cmdUpdate 处理 update 命令
func cmdUpdate(flags caddycmd.Flags) (int, error) {
    fmt.Println("🚀 开始更新天神之眼...")

    // 确保文件已解压
    if err := extractEmbeddedFiles(); err != nil {
        fmt.Printf("❌ 释出配置文件失败: %v\n", err)
        return 1, err
    }

    // 运行更新脚本
    scriptPath := "/etc/caddy/update.sh"
    return runScript(scriptPath, "更新")
}

// cmdBackup 处理 backup 命令
func cmdBackup(flags caddycmd.Flags) (int, error) {
    fmt.Println("🗄️ 开始备份天神之眼数据...")

    // 确保文件已解压
    if err := extractEmbeddedFiles(); err != nil {
        fmt.Printf("❌ 释出配置文件失败: %v\n", err)
        return 1, err
    }

    // 运行备份脚本
    scriptPath := "/etc/caddy/backup.sh"
    return runScript(scriptPath, "备份")
}

// cmdRestore 处理 restore 命令
func cmdRestore(flags caddycmd.Flags) (int, error) {
    fmt.Println("🔄 开始恢复天神之眼数据...")

    // 确保文件已解压
    if err := extractEmbeddedFiles(); err != nil {
        fmt.Printf("❌ 释出配置文件失败: %v\n", err)
        return 1, err
    }

    // 运行恢复脚本
    scriptPath := "/etc/caddy/restore.sh"
    return runScript(scriptPath, "恢复")
}

// cmdUninstall 处理 uninstall 命令
func cmdUninstall(flags caddycmd.Flags) (int, error) {
    fmt.Println("🗑️ 开始卸载天神之眼...")

    // 确保文件已解压
    if err := extractEmbeddedFiles(); err != nil {
        fmt.Printf("❌ 释出配置文件失败: %v\n", err)
        return 1, err
    }

    // 运行卸载脚本
    scriptPath := "/etc/caddy/uninstall.sh"
    return runScript(scriptPath, "卸载")
}

// runScript 通用脚本执行函数
func runScript(scriptPath, operation string, args ...string) (int, error) {
   // 检查脚本是否存在
    if _, err := os.Stat(scriptPath); os.IsNotExist(err) {
        return 1, fmt.Errorf("%s配置文件不存在: %s", operation, scriptPath)
    }

    // 设置脚本为可执行
    if err := os.Chmod(scriptPath, 0755); err != nil {
        return 1, fmt.Errorf("设置权限失败: %v", err)
    }

    // 构建命令参数
    var cmdArgs []string
    if len(args) > 0 {
        cmdArgs = args
    } else {
        cmdArgs = []string{scriptPath}
    }

    // 执行脚本
    cmd := exec.Command("/bin/bash", cmdArgs...)
    cmd.Stdout = os.Stdout
    cmd.Stderr = os.Stderr
    cmd.Stdin = os.Stdin

    if err := cmd.Run(); err != nil {
        fmt.Printf("❌ %s执行失败: %v\n", operation, err)
        fmt.Printf("💡 您也可以手动运行: sudo %s\n", scriptPath)
        return 1, err
    }

    fmt.Printf("✅ %s完成！🎉\n", operation)
    return 0, nil
}


// cmdAutoUpdate 处理自动更新设置命令
func cmdAutoUpdate(flags caddycmd.Flags) (int, error) {
    enable := flags.Bool("enable")
    disable := flags.Bool("disable")
    status := flags.Bool("status")
    
    fmt.Println("⚙️ 天神之眼自动更新设置...")
    
    // 确保文件已解压
    if err := extractEmbeddedFiles(); err != nil {
        fmt.Printf("❌ 释出配置文件失败: %v\n", err)
        return 1, err
    }
    
    scriptPath := "/etc/caddy/autoupdate_setup.sh"
    
    // 根据参数选择操作
    if enable {
        return runScript(scriptPath, "启用自动更新", scriptPath, "enable")
    } else if disable {
        return runScript(scriptPath, "禁用自动更新", scriptPath, "disable")
    } else if status {
        return runScript(scriptPath, "查看自动更新状态", scriptPath, "status")
    } else {
        // 默认启动交互式设置
        return runScript(scriptPath, "自动更新设置")
    }
}



// forceExtractScripts 强制解压嵌入的zip文件中的脚本文件到指定目录
func forceExtractScripts() error {
    // 创建目标目录
    if err := os.MkdirAll(extractPath, 0755); err != nil {
        return fmt.Errorf("failed to create directory %s: %v", extractPath, err)
    }

    // 创建zip reader
    zipReader, err := zip.NewReader(strings.NewReader(string(embeddedFiles)), int64(len(embeddedFiles)))
    if err != nil {
        return fmt.Errorf("failed to create zip reader: %v", err)
    }

    var extractedCount int
    var scriptCount int

    // 解压文件
    for _, file := range zipReader.File {
        // 构建完整路径
        fullPath := filepath.Join(extractPath, file.Name)

        // 确保路径安全（防止路径遍历攻击）
        if !strings.HasPrefix(fullPath, extractPath) {
            continue
        }

        // 只处理 .sh 脚本文件
        if !strings.HasSuffix(strings.ToLower(file.Name), ".sh") {
            continue
        }

        scriptCount++

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

        // 创建目标文件（覆盖模式）
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

        // 设置脚本为可执行
        if err := os.Chmod(fullPath, 0755); err != nil {
            fmt.Printf("⚠️ 警告: 设置 %s 权限失败: %v\n", fullPath, err)
        }

        extractedCount++
        fmt.Printf("✅ 已更新功能配置文件: %s\n", file.Name)
    }

    if scriptCount == 0 {
        return fmt.Errorf("zip文件中未找到任何 .sh 脚本文件")
    }

    fmt.Printf("📊 统计: 共找到 %d 个功能配置文件，成功更新 %d 个\n", scriptCount, extractedCount)
    return nil
}

// extractScriptsOnly 仅解压脚本文件的函数
func extractScriptsOnly() error {
    // 创建目标目录
    if err := os.MkdirAll(extractPath, 0755); err != nil {
        return fmt.Errorf("failed to create directory %s: %v", extractPath, err)
    }

    // 创建zip reader
    zipReader, err := zip.NewReader(strings.NewReader(string(embeddedFiles)), int64(len(embeddedFiles)))
    if err != nil {
        return fmt.Errorf("failed to create zip reader: %v", err)
    }

    var extractedCount int
    var scriptCount int

    // 解压文件
    for _, file := range zipReader.File {
        // 构建完整路径
        fullPath := filepath.Join(extractPath, file.Name)

        // 确保路径安全（防止路径遍历攻击）
        if !strings.HasPrefix(fullPath, extractPath) {
            continue
        }

        // 只处理 .sh 脚本文件
        if !strings.HasSuffix(strings.ToLower(file.Name), ".sh") {
            continue
        }

        scriptCount++

        if file.FileInfo().IsDir() {
            continue
        }

        // 检查文件是否已存在且较新
        if fileInfo, err := os.Stat(fullPath); err == nil {
            // 文件已存在，检查是否需要更新
            if fileInfo.ModTime().After(file.FileInfo().ModTime()) {
                fmt.Printf("⏭️ 跳过较新的功能配置文件: %s\n", file.Name)
                continue
            }
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

        // 设置脚本为可执行
        if err := os.Chmod(fullPath, 0755); err != nil {
            fmt.Printf("⚠️ 警告: 设置 %s 权限失败: %v\n", fullPath, err)
        }

        extractedCount++
        fmt.Printf("✅ 已更新功能配置文件: %s\n", file.Name)
    }

    if scriptCount == 0 {
        return fmt.Errorf("未找到任何功能配置文件")
    }

    fmt.Printf("📊 统计: 共找到 %d 个功能配置文件，成功更新 %d 个\n", scriptCount, extractedCount)
    return nil
}


// cmdUpdateScripts 处理更新脚本命令
func cmdUpdateScripts(flags caddycmd.Flags) (int, error) {
    force := flags.Bool("force")
    
    fmt.Println("📝 开始更新天神之眼功能配置文件...")
    
    if force {
        fmt.Println("🔄 强制模式：将覆盖所有现有功能配置文件")
        
        // 强制更新所有脚本文件
        if err := forceExtractScripts(); err != nil {
            fmt.Printf("❌ 强制更新功能配置文件失败: %v\n", err)
            return 1, err
        }
        
        fmt.Println("✅ 强制更新功能配置文件完成！🎉")
    } else {
        fmt.Println("🔍 智能模式：仅更新需要更新的功能配置文件")
        
        // 智能更新脚本文件
        if err := extractScriptsOnly(); err != nil {
            fmt.Printf("❌ 更新功能配置文件失败: %v\n", err)
            return 1, err
        }
        
        fmt.Println("✅ 智能更新功能配置文件完成！🎉")
    }
    
    // 显示可用的脚本文件
    fmt.Println("\n📋 当前可用的功能配置文件:")
    if files, err := filepath.Glob(filepath.Join(extractPath, "*.sh")); err == nil {
        for _, file := range files {
            fileName := filepath.Base(file)
            if fileInfo, err := os.Stat(file); err == nil {
                fmt.Printf("  📄 %s (修改时间: %s)\n", fileName, fileInfo.ModTime().Format("2006-01-02 15:04:05"))
            } else {
                fmt.Printf("  📄 %s\n", fileName)
            }
        }
    } else {
        fmt.Printf("⚠️ 无法列出功能配置文件: %v\n", err)
    }
    
    fmt.Println("\n💡 提示:")
    fmt.Println("  - 使用 --force 参数强制覆盖所有功能配置文件")
    fmt.Println("  - 所有功能配置文件已自动设置为可执行权限")
  //  fmt.Printf("  - 脚本文件位置: %s\n", extractPath)
    
    return 0, nil
}


