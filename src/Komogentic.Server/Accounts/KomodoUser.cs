// SPDX-License-Identifier: AGPL-3.0-or-later
namespace Komogentic.Server.Accounts;

/// <summary>A Komodo user as Komogentic knows them: Komodo's user id and username. There are no accounts of Komogentic's own.</summary>
public sealed record KomodoUser(string Id, string Username);
