using TencentCloud.Common;
using TencentCloud.Common.Profile;
using TencentCloud.Sms.V20210111;
using TencentCloud.Sms.V20210111.Models;

namespace SignaCore.Domain.Services.Sms;

public sealed class TencentCloudSmsSender : ISmsSender
{
    private readonly System.Runtime.CompilerServices.ConditionalWeakTable<SmsProviderProfile, SmsClient> _clients = new();

    public string Provider => SmsProviderNames.TencentCloud;

    public async Task<SmsSendResult> SendAsync(
        SmsProviderProfile profile,
        SmsVerificationMessage message,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var client = _clients.GetValue(profile, static value => new SmsClient(
            new Credential { SecretId = value.AccessKeyId, SecretKey = value.AccessKeySecret },
            value.Region!,
            new ClientProfile
            {
                HttpProfile = new HttpProfile { Endpoint = "sms.tencentcloudapi.com", Timeout = 10 }
            }));
        var response = await client.SendSms(new SendSmsRequest
        {
            PhoneNumberSet = [message.PhoneE164],
            SmsSdkAppId = profile.SmsSdkAppId,
            SignName = profile.SignName,
            TemplateId = profile.TemplateId,
            TemplateParamSet = [message.Code],
            SessionContext = message.ReferenceId
        });
        var status = response.SendStatusSet?.SingleOrDefault();
        if (status == null || !string.Equals(status.Code, "Ok", StringComparison.Ordinal))
            throw new SmsDeliveryRejectedException(status?.Code ?? "Unknown", status?.Message);
        return new SmsSendResult(Provider, status.SerialNo);
    }
}
