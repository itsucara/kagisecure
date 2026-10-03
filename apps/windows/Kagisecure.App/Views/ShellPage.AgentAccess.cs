using System;
using System.Collections.Generic;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace Kagisecure.App.Views;

/// <summary>One row of the sidebar's Agent access group (ui-spec.md §2.2, §10.4).</summary>
public sealed class AgentAccessNode
{
    public AgentAccessNode(string displayName, string glyph, Type pageType, string automationId)
    {
        DisplayName = displayName;
        Glyph = glyph;
        PageType = pageType;
        AutomationId = automationId;
    }

    public string DisplayName { get; }

    /// <summary>A Segoe Fluent Icons glyph.</summary>
    public string Glyph { get; }

    public Type PageType { get; }

    public string AutomationId { get; }

    /// <summary>The group, in order.</summary>
    public static IReadOnlyList<AgentAccessNode> All { get; } = new[]
    {
        new AgentAccessNode("Environments", "", typeof(EnvironmentsPage), "ks.sidebar.environments"),
        new AgentAccessNode("Leases", "", typeof(LeasesPage), "ks.sidebar.leases"),
        new AgentAccessNode("Set up your agent", "", typeof(McpSetupPage), "ks.sidebar.agentSetup"),
        new AgentAccessNode("Browser extension", "", typeof(BrowserExtensionPage), "ks.sidebar.browserExtension"),
        new AgentAccessNode("Security (Windows Hello)", "", typeof(SecuritySettingsPage), "ks.sidebar.security"),
    };
}

/// <summary>
/// The Agent access group of the sidebar. Its pages open in a frame laid over the item list and
/// detail panes, so the item side's own navigation is untouched: choosing any item section again
/// hides the frame.
/// </summary>
public sealed partial class ShellPage
{
    public IReadOnlyList<AgentAccessNode> AgentAccessNodes => AgentAccessNode.All;

    private void OnAgentAccessSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (AgentAccessList.SelectedItem is not AgentAccessNode node)
        {
            return;
        }

        TopList.SelectedItem = null;
        CategoryList.SelectedItem = null;
        TagList.SelectedItem = null;
        BottomList.SelectedItem = null;
        AgentAccessFrame.Visibility = Visibility.Visible;
        AgentAccessFrame.Navigate(node.PageType);
        AgentAccessFrame.BackStack.Clear();
    }

    /// <summary>Hide the Agent access frame, letting its page go (its OnNavigatedFrom unsubscribes from the host).</summary>
    private void HideAgentAccessPane()
    {
        AgentAccessList.SelectedItem = null;
        if (AgentAccessFrame.Visibility == Visibility.Collapsed)
        {
            return;
        }

        AgentAccessFrame.Visibility = Visibility.Collapsed;
        AgentAccessFrame.Navigate(typeof(Page));
        AgentAccessFrame.BackStack.Clear();
    }
}
