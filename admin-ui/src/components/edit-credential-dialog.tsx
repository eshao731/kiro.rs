import { useState, useEffect } from 'react'
import { toast } from 'sonner'
import { useQuery } from '@tanstack/react-query'
import { Copy, Eye, EyeOff, Loader2 } from 'lucide-react'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import {
  Select,
  SelectGroup,
  SelectLabel,
  SelectTrigger,
  SelectValue,
  SelectContent,
  SelectItem,
} from '@/components/ui/select'
import { Input } from '@/components/ui/input'
import { useUpdateCredential } from '@/hooks/use-credentials'
import { useGroupOptions } from '@/hooks/use-groups'
import { getCredentialApiKey, getProxyPool } from '@/api/credentials'
import { extractErrorMessage, maskProxyUrl } from '@/lib/utils'
import { GroupMultiSelect } from '@/components/group-select'
import type { CredentialStatusItem } from '@/types/api'

interface EditCredentialDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  credential: CredentialStatusItem
}

export function EditCredentialDialog({
  open,
  onOpenChange,
  credential,
}: EditCredentialDialogProps) {
  const [email, setEmail] = useState(credential.email ?? '')
  const [proxyUrl, setProxyUrl] = useState(credential.proxyUrl ?? '')
  const [proxyUsername, setProxyUsername] = useState('')
  const [proxyPassword, setProxyPassword] = useState('')
  const [groups, setGroups] = useState<string[]>(credential.groups ?? [])
  const [sourceChannel, setSourceChannel] = useState(credential.sourceChannel ?? '')
  const [manualMode, setManualMode] = useState(false)
  const [apiKey, setApiKey] = useState('')
  const [showApiKey, setShowApiKey] = useState(false)
  const [loadingApiKey, setLoadingApiKey] = useState(false)

  const groupOptions = useGroupOptions()

  const { data: proxyPool } = useQuery({
    queryKey: ['proxy-pool'],
    queryFn: getProxyPool,
    enabled: open,
  })

  // 每次打开时重置表单为当前凭据值
  useEffect(() => {
    if (open) {
      setEmail(credential.email ?? '')
      setProxyUrl(credential.proxyUrl ?? '')
      setProxyUsername('')
      setProxyPassword('')
      setGroups(credential.groups ?? [])
      setSourceChannel(credential.sourceChannel ?? '')
      setManualMode(false)
      setApiKey('')
      setShowApiKey(false)
    } else {
      setApiKey('')
      setShowApiKey(false)
    }
  }, [open, credential])

  const { mutate, isPending } = useUpdateCredential()

  const handleRevealApiKey = async () => {
    setLoadingApiKey(true)
    try {
      const response = await getCredentialApiKey(credential.id)
      setApiKey(response.kiroApiKey)
      setShowApiKey(true)
    } catch (error) {
      toast.error(`获取 API Key 失败: ${extractErrorMessage(error)}`)
    } finally {
      setLoadingApiKey(false)
    }
  }

  const handleCopyApiKey = async () => {
    try {
      await navigator.clipboard.writeText(apiKey)
      toast.success('API Key 已复制')
    } catch {
      toast.error('复制失败，请手动选择复制')
    }
  }

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()

    mutate(
      {
        id: credential.id,
        req: {
          email: email,
          proxyUrl: proxyUrl,
          proxyUsername: proxyUsername || undefined,
          proxyPassword: proxyPassword || undefined,
          groups: groups,
          sourceChannel: sourceChannel,
        },
      },
      {
        onSuccess: (data) => {
          toast.success(data.message)
          onOpenChange(false)
        },
        onError: (error: unknown) => {
          toast.error(`更新失败: ${extractErrorMessage(error)}`)
        },
      }
    )
  }

  const enabledProxies = proxyPool?.proxies.filter(p => p.enabled) ?? []

  // 当前 proxyUrl 是否是自定义值（不匹配任何标准选项）
  const isCustomUrl = proxyUrl !== '' && proxyUrl !== 'direct' &&
    !enabledProxies.some(p => p.url === proxyUrl)

  // 显示手动输入框：明确进入手动模式，或当前值就是自定义值
  const showManualInput = manualMode || isCustomUrl

  const selectValue = showManualInput ? '__custom__' : proxyUrl

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>
            编辑凭据 #{credential.id}
          </DialogTitle>
        </DialogHeader>

        <form onSubmit={handleSubmit} autoComplete="off">
          <div className="space-y-4 py-4">
            {credential.authMethod === 'api_key' && (
              <div className="space-y-2 rounded-xl border border-border/60 bg-secondary/30 p-3">
                <label className="text-sm font-medium">Kiro API Key</label>
                {apiKey ? (
                  <div className="flex gap-2">
                    <Input
                      type={showApiKey ? 'text' : 'password'}
                      value={apiKey}
                      readOnly
                      className="font-mono text-sm"
                    />
                    <Button
                      type="button"
                      size="icon"
                      variant="outline"
                      onClick={() => setShowApiKey((value) => !value)}
                      title={showApiKey ? '隐藏 API Key' : '显示 API Key'}
                    >
                      {showApiKey ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                    </Button>
                    <Button
                      type="button"
                      size="icon"
                      variant="outline"
                      onClick={handleCopyApiKey}
                      title="复制 API Key"
                    >
                      <Copy className="h-4 w-4" />
                    </Button>
                  </div>
                ) : (
                  <Button
                    type="button"
                    variant="outline"
                    className="w-full"
                    onClick={handleRevealApiKey}
                    disabled={loadingApiKey}
                  >
                    {loadingApiKey && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                    查看 API Key
                  </Button>
                )}
                <p className="text-xs text-muted-foreground">
                  仅在点击后通过管理员认证接口获取，关闭弹窗后会从页面状态中清除。
                </p>
              </div>
            )}

            {/* 邮箱 */}
            <div className="space-y-2">
              <label htmlFor="email" className="text-sm font-medium">
                邮箱（用于显示标识）
              </label>
              <Input
                id="email"
                type="email"
                autoComplete="off"
                placeholder="例: user@example.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                disabled={isPending}
              />
              <p className="text-xs text-muted-foreground">
                留空则显示凭据 ID，清除请提交空值
              </p>
            </div>

            {/* 账号分组 */}
            <div className="space-y-2">
              <label className="text-sm font-medium">账号分组</label>
              <GroupMultiSelect
                value={groups}
                options={groupOptions}
                onChange={setGroups}
                disabled={isPending}
              />
              <p className="text-xs text-muted-foreground">
                绑定了某分组的客户端 Key 只会调度到含该分组的账号。不选表示不属于任何分组。
              </p>
            </div>

            {/* 账号来源渠道 */}
            <div className="space-y-2">
              <label htmlFor="sourceChannel" className="text-sm font-medium">
                账号来源渠道（备注）
              </label>
              <Input
                id="sourceChannel"
                placeholder="例: 官方, 转售商A, 采购平台X"
                value={sourceChannel}
                onChange={(e) => setSourceChannel(e.target.value)}
                disabled={isPending}
              />
              <p className="text-xs text-muted-foreground">
                纯备注，标记此账号的购买来源/渠道，便于追踪。留空表示清除。
              </p>
            </div>

            {/* 代理配置 */}
            <div className="space-y-2">
              <label className="text-sm font-medium">代理配置</label>

              {/* 下拉选择代理 */}
              <Select
                value={selectValue === '' ? '__global__' : selectValue}
                onValueChange={(val) => {
                  if (val === '__custom__') {
                    setManualMode(true)
                    // 保留当前 proxyUrl 作为初始值让用户编辑
                  } else {
                    setManualMode(false)
                    setProxyUrl(val === '__global__' ? '' : val)
                  }
                }}
                disabled={isPending}
              >
                <SelectTrigger className="h-10 rounded-xl px-3.5">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="__global__">使用全局代理配置</SelectItem>
                  <SelectItem value="direct">直连（不使用代理）</SelectItem>
                  {enabledProxies.length > 0 && (
                    <SelectGroup>
                      <SelectLabel>代理池</SelectLabel>
                      {enabledProxies.map((p) => (
                        <SelectItem key={p.id} value={p.url}>
                          {p.label ? `${p.label} | ${maskProxyUrl(p.url)}` : maskProxyUrl(p.url)}
                        </SelectItem>
                      ))}
                    </SelectGroup>
                  )}
                  <SelectItem value="__custom__">手动输入...</SelectItem>
                </SelectContent>
              </Select>

              {/* 自定义 URL 手动输入框 */}
              {showManualInput && (
                <Input
                  placeholder='自定义代理 URL（如 socks5://user:pass@host:port）'
                  value={proxyUrl}
                  onChange={(e) => setProxyUrl(e.target.value)}
                  disabled={isPending}
                  className="font-mono text-sm"
                />
              )}

              {/* 代理认证（仅在需要时显示） */}
              <div className="grid grid-cols-2 gap-2">
                <Input
                  id="proxyUsername"
                  name="kiro-proxy-auth-user"
                  autoComplete="off"
                  data-1p-ignore
                  data-bwignore
                  data-lpignore="true"
                  placeholder="代理用户名（留空不修改）"
                  value={proxyUsername}
                  onChange={(e) => setProxyUsername(e.target.value)}
                  disabled={isPending}
                />
                <Input
                  id="proxyPassword"
                  name="kiro-proxy-auth-secret"
                  type="password"
                  autoComplete="new-password"
                  data-1p-ignore
                  data-bwignore
                  data-lpignore="true"
                  placeholder="代理密码（留空不修改）"
                  value={proxyPassword}
                  onChange={(e) => setProxyPassword(e.target.value)}
                  disabled={isPending}
                />
              </div>
              <p className="text-xs text-muted-foreground">
                用户名/密码留空表示不修改；代理 URL 已包含凭据时无需填写
              </p>
            </div>
          </div>

          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              onClick={() => onOpenChange(false)}
              disabled={isPending}
            >
              取消
            </Button>
            <Button type="submit" disabled={isPending}>
              {isPending ? '保存中...' : '保存'}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
