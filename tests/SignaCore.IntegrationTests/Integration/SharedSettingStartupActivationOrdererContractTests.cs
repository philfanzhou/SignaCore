using System.Reflection;
using Moq;
using Xunit;
using Xunit.Sdk;

namespace SignaCore.Tests.Integration;

/// <summary>
/// The mechanical proof of the intra-class execution-order contract of
/// <see cref="SharedSettingStartupActivationTests"/> (issue #320). The class shares one fixture
/// database across its cases, and exactly one case commits a change to it; the orderer must place
/// that mutating case after every read-only case for any input order, so the assertions no longer
/// depend on the compile-artifact discovery order that made the failure drift between trees. This
/// mirrors how <c>SqliteProcessStateContractTests</c> pins the pool-clearing collection contract.
/// </summary>
public sealed class SharedSettingStartupActivationOrdererContractTests
{
    private const string MutatingTest =
        nameof(SharedSettingStartupActivationTests
            .TwoHosts_ObserveTheSameVersionAndSnapshot_AndVersionsAdvanceMonotonically);

    /// <summary>
    /// The cases that only read the shared fixture database and must therefore run before the one
    /// mutating case. Every <c>[Fact]</c> on the class has to be classified here or as the mutating
    /// case, so a newly added case cannot silently inherit an unsafe position in the order.
    /// </summary>
    private static readonly string[] ReadOnlyTests =
    [
        nameof(SharedSettingStartupActivationTests
            .ActivatedProjection_IsEquivalentToTheLegacySnapshotPath),
        nameof(SharedSettingStartupActivationTests
            .StartupMigration_LeavesTheLegacyRowsUntouched),
    ];

    /// <summary>
    /// The orderer is actually applied to the class: without the attribute the contract is only a
    /// type that nothing invokes, and xUnit falls back to discovery order.
    /// </summary>
    [Fact]
    public void TheTestClass_AppliesTheOrderer()
    {
        var attribute = typeof(SharedSettingStartupActivationTests)
            .GetCustomAttribute<TestCaseOrdererAttribute>();

        Assert.NotNull(attribute);
        Assert.Equal(typeof(SharedSettingStartupActivationTestOrderer), attribute!.OrdererType);
    }

    /// <summary>
    /// Every <c>[Fact]</c> on the class is explicitly classified as read-only or as the single
    /// database-mutating case. A new case that is not classified fails here, forcing the author to
    /// decide whether it commits to the shared database (and, if so, to add it to the orderer's
    /// mutating set) rather than letting it drift into an order that re-breaks the pristine reads.
    /// </summary>
    [Fact]
    public void EveryFactOnTheTestClass_IsExplicitlyClassified()
    {
        var factMethods = typeof(SharedSettingStartupActivationTests)
            .GetMethods(BindingFlags.Public | BindingFlags.Instance)
            .Where(method => method.GetCustomAttribute<FactAttribute>() is not null)
            .Select(method => method.Name)
            .Order(StringComparer.Ordinal)
            .ToArray();

        var classified = ReadOnlyTests
            .Concat([MutatingTest])
            .Order(StringComparer.Ordinal)
            .ToArray();

        Assert.Equal(classified, factMethods);
    }

    /// <summary>
    /// For every permutation of the class's real <c>[Fact]</c> methods, the orderer runs the single
    /// database-mutating case last and keeps the read-only cases ahead of it in a deterministic
    /// order. Feeding the mutating case first is exactly the discovery order that broke the
    /// pristine read before the fix.
    /// </summary>
    [Fact]
    public void TheOrderer_RunsTheDatabaseMutatingCaseLast_ForEveryInputOrder()
    {
        var factMethods = typeof(SharedSettingStartupActivationTests)
            .GetMethods(BindingFlags.Public | BindingFlags.Instance)
            .Where(method => method.GetCustomAttribute<FactAttribute>() is not null)
            .Select(method => method.Name)
            .ToArray();

        // The contract is only meaningful while the class really has the one mutating case among
        // its facts; a rename or a new mutating fact must surface here rather than silently pass.
        Assert.Contains(MutatingTest, factMethods);

        var orderer = new SharedSettingStartupActivationTestOrderer();
        foreach (var permutation in Permute(factMethods))
        {
            var ordered = orderer
                .OrderTestCases(permutation.Select(FakeTestCase).ToList())
                .Select(testCase => testCase.TestMethod!.MethodName)
                .ToArray();

            Assert.Equal(factMethods.Length, ordered.Length);
            Assert.Equal(MutatingTest, ordered[^1]);
            Assert.Equal(
                factMethods.Where(name => name != MutatingTest).Order(StringComparer.Ordinal),
                ordered[..^1].Order(StringComparer.Ordinal));
        }
    }

    private static ITestCase FakeTestCase(string methodName)
    {
        var method = new Mock<ITestMethod>();
        method.Setup(item => item.MethodName).Returns(methodName);
        var testCase = new Mock<ITestCase>();
        testCase.Setup(item => item.TestMethod).Returns(method.Object);
        return testCase.Object;
    }

    private static IEnumerable<T[]> Permute<T>(T[] items)
    {
        if (items.Length <= 1)
        {
            yield return items;
            yield break;
        }

        for (var index = 0; index < items.Length; index++)
        {
            var rest = items.Where((_, position) => position != index).ToArray();
            foreach (var tail in Permute(rest))
            {
                yield return new[] { items[index] }.Concat(tail).ToArray();
            }
        }
    }
}
