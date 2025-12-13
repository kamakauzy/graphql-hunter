from graphql_hunter.lib.graphql_client import GraphQLClient


def test_graphql_client_instantiation():
    """Ensure GraphQLClient can be instantiated with a dummy endpoint."""
    client = GraphQLClient(url="https://countries.trevorblades.com/graphql")
    assert client is not None
