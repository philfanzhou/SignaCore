namespace SignaCore.Database.Entity;

public enum OtpStatus
{
    PendingDelivery = 0,
    Sent = 1,
    Consumed = 2,
    DeliveryFailed = 3
}
