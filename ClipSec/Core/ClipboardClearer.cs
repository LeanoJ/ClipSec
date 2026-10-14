using System.Windows.Threading;
using ClipSec.Native;

namespace ClipSec.Core;

/// <summary>
/// Leert die Zwischenablage nach Ablauf einer Frist – aber nur, wenn der Benutzer
/// in der Zwischenzeit nichts anderes kopiert hat (Vergleich der Sequenznummer).
/// </summary>
internal sealed class ClipboardClearer
{
    private readonly DispatcherTimer _timer = new();
    private uint _sequence;

    public ClipboardClearer()
    {
        _timer.Tick += (_, _) =>
        {
            _timer.Stop();
            ClipboardAccess.ClearIfUnchanged(_sequence);
        };
    }

    /// <summary>Plant das Leeren. Mehrere Fristen: die kürzeste ungleich 0 gilt.</summary>
    public void Schedule(uint sequence, params int[] seconds)
    {
        var delay = seconds.Where(s => s > 0).DefaultIfEmpty(0).Min();
        if (delay <= 0) return;
        _timer.Stop();
        _sequence = sequence;
        _timer.Interval = TimeSpan.FromSeconds(delay);
        _timer.Start();
    }

    /// <summary>Für Inhalte, die jetzt gerade in der Zwischenablage liegen (aus anderen Programmen kopiert).</summary>
    public void ScheduleForCurrent(params int[] seconds) =>
        Schedule(NativeMethods.GetClipboardSequenceNumber(), seconds);
}
