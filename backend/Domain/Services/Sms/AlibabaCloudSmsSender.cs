using AlibabaCloud.OpenApiClient.Models;
using AlibabaCloud.SDK.Dysmsapi20170525.Models;
using AlibabaCloud.TeaUtil.Models;

namespace QuantumZhou.Identity.Domain.Services.Sms;

public sealed class AlibabaCloudSmsSender : ISmsSender
{
    private readonly System.Runtime.CompilerServices.ConditionalWeakTable<
        SmsProviderProfile, AlibabaCloud.SDK.Dysmsapi20170525.Client> _clients = new();

    public string Provider => SmsProviderNames.AlibabaCloud;

    public async Task<SmsSendResult> SendAsync(
        SmsProviderProfile profile,
        SmsVerificationMessage message,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var client = _clients.GetValue(profile, static value =>
            new AlibabaCloud.SDK.Dysmsapi20170525.Client(new Config
            {
                AccessKeyId = value.AccessKeyId,
                AccessKeySecret = value.AccessKeySecret,
                Endpoint = "dysmsapi.aliyuncs.com"
            }));
        var response = await client.SendSmsWithOptionsAsync(new SendSmsRequest
        {
            PhoneNumbers = message.PhoneE164[3..],
            SignName = profile.SignName,
            TemplateCode = profile.TemplateId,
            TemplateParam = System.Text.Json.JsonSerializer.Serialize(new { code = message.Code }),
            OutId = message.ReferenceId
        }, new RuntimeOptions
        {
            Autoretry = false,
            ConnectTimeout = 5000,
            ReadTimeout = 10000
        });
        if (!string.Equals(response.Body.Code, "OK", StringComparison.Ordinal))
            throw new SmsDeliveryRejectedException(response.Body.Code ?? "Unknown", response.Body.Message);
        return new SmsSendResult(Provider, response.Body.BizId);
    }
}
